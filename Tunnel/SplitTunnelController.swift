import Foundation
import Network
import NetworkExtension

/// Immutable description of the tunnel interface used to rebuild network
/// settings without restarting the AmneziaWG data plane.
public struct SplitInterfaceSettings: Sendable {
    public var remoteAddress: String
    public var ipv4Addresses: [(address: String, subnetMask: String)]
    public var ipv6Addresses: [(address: String, prefixLength: UInt8)]
    public var dnsServers: [String]
    public var mtu: Int

    public init(
        remoteAddress: String,
        ipv4Addresses: [(address: String, subnetMask: String)],
        ipv6Addresses: [(address: String, prefixLength: UInt8)],
        dnsServers: [String],
        mtu: Int
    ) {
        self.remoteAddress = remoteAddress
        self.ipv4Addresses = ipv4Addresses
        self.ipv6Addresses = ipv6Addresses
        self.dnsServers = dnsServers
        self.mtu = mtu
    }
}

public enum SplitTunnelError: LocalizedError, Sendable {
    case noEnabledLists
    case noResolvedRoutes
    case invalidRoute(String)
    case settingsFailed(String)

    public var errorDescription: String? {
        switch self {
        case .noEnabledLists:
            return "Раздельное туннелирование включено, но не выбран ни один список доменов."
        case .noResolvedRoutes:
            return "DNS не вернул ни одного реального A/AAAA адреса для выбранных доменов. Полный туннель автоматически не включается."
        case .invalidRoute(let route):
            return "Некорректный точный маршрут: \(route)"
        case .settingsFailed(let message):
            return "Не удалось применить маршруты split tunneling: \(message)"
        }
    }
}

/// Connects DomainRouter to NEPacketTunnelProvider.
///
/// WireGuard peer AllowedIPs remain `0.0.0.0/0, ::/0`, so the AWG core can
/// encrypt every destination. Only NE `includedRoutes` are narrowed to exact
/// DNS-derived /32 and /128 addresses. This is the routing boundary: all other
/// traffic stays on the physical interface. No FakeIP and no /24 aggregation.
final class SplitTunnelController {
    private let router: DomainRouter
    private let resolver: NWUDPUpstreamResolver
    private var refreshTask: Task<Void, Never>?
    private var baseSettings: SplitInterfaceSettings?

    init(dnsServers: [String] = []) {
        self.router = DomainRouter()
        let upstream = dnsServers.first(where: { IPv4Address($0) != nil }) ?? "1.1.1.1"
        self.resolver = NWUDPUpstreamResolver(host: upstream, port: 53, timeout: 5)
    }

    /// Loads all selected lists and resolves every listed base domain before
    /// starting the tunnel. A failed initial load is explicit; it never falls
    /// back to capturing the whole device.
    @discardableResult
    func prepare(descriptors: [DomainListDescriptor]) async throws -> RouteSnapshot {
        let sources = descriptors.filter(\.enabled).map {
            DomainListSource(id: $0.id, url: $0.url)
        }
        guard !sources.isEmpty else { throw SplitTunnelError.noEnabledLists }

        _ = try await router.refresh(sources: sources, timeout: 15, maxConcurrentLoads: 4)
        let domains = await router.snapshot.rules.map(\.domain)
        let uniqueDomains = Array(Set(domains)).sorted()

        await withTaskGroup(of: Void.self) { group in
            let workers = min(4, max(1, uniqueDomains.count))
            // Fixed partitions avoid sharing a mutable iterator between tasks.
            for worker in 0..<workers {
                let partition = uniqueDomains.indices.filter { $0 % workers == worker }.map { uniqueDomains[$0] }
                group.addTask { [router, resolver] in
                    for domain in partition {
                        for family in IPAddressFamily.allCases {
                            guard !Task.isCancelled else { return }
                            do {
                                let addresses = try await resolver.resolve(domain: domain, family: family)
                                try await router.recordResolution(
                                    domain: domain,
                                    addresses: addresses,
                                    family: family
                                )
                            } catch {
                                // One family/domain failure must not erase the
                                // rest of the resolved exact routes.
                            }
                        }
                    }
                }
            }
        }

        let snapshot = await router.currentRouteSnapshot
        guard !snapshot.routes.isEmpty else { throw SplitTunnelError.noResolvedRoutes }
        return snapshot
    }

    func apply(
        routes: RouteSnapshot,
        to provider: NEPacketTunnelProvider,
        base: SplitInterfaceSettings
    ) async throws {
        let settings = try makeNetworkSettings(routes: routes, base: base)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            provider.setTunnelNetworkSettings(settings) { error in
                if let error {
                    continuation.resume(throwing: SplitTunnelError.settingsFailed(error.localizedDescription))
                } else {
                    continuation.resume()
                }
            }
        }
        baseSettings = base
    }

    /// Starts TTL-based route updates. The NE session and AWG interface stay up;
    /// only includedRoutes change. Cancellation is cooperative in stop().
    func startRefresh(
        provider: NEPacketTunnelProvider,
        base: SplitInterfaceSettings,
        interval: TimeInterval = 30
    ) {
        stopRefresh()
        baseSettings = base
        refreshTask = Task { [router, resolver, weak self, weak provider] in
            await router.runRouteRefreshLoop(using: resolver, interval: interval) { snapshot in
                guard let self, let provider, !Task.isCancelled else { return }
                // DomainRouter callback is synchronous; NE settings update is async.
                Task { [weak self, weak provider] in
                    guard let self, let provider else { return }
                    do {
                        try await self.apply(routes: snapshot, to: provider, base: base)
                    } catch {
                        NSLog("[OmniWARP][split] route update failed: %@", error.localizedDescription)
                    }
                }
            }
        }
    }

    func stopRefresh() {
        refreshTask?.cancel()
        refreshTask = nil
    }

    func makeNetworkSettings(
        routes: RouteSnapshot,
        base: SplitInterfaceSettings
    ) throws -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: base.remoteAddress)
        settings.mtu = NSNumber(value: base.mtu)

        if !base.ipv4Addresses.isEmpty {
            let ipv4 = NEIPv4Settings(
                addresses: base.ipv4Addresses.map(\.address),
                subnetMasks: base.ipv4Addresses.map(\.subnetMask)
            )
            ipv4.includedRoutes = try routes.routes.compactMap { route -> NEIPv4Route? in
                guard route.prefixLength == 32 else { return nil }
                return NEIPv4Route(destinationAddress: route.address, subnetMask: "255.255.255.255")
            }
            settings.ipv4Settings = ipv4
        }

        if !base.ipv6Addresses.isEmpty {
            let ipv6 = NEIPv6Settings(
                addresses: base.ipv6Addresses.map(\.address),
                networkPrefixLengths: base.ipv6Addresses.map { NSNumber(value: $0.prefixLength) }
            )
            ipv6.includedRoutes = routes.routes.compactMap { route -> NEIPv6Route? in
                guard route.prefixLength == 128 else { return nil }
                return NEIPv6Route(destinationAddress: route.address, networkPrefixLength: NSNumber(value: 128))
            }
            settings.ipv6Settings = ipv6
        }

        if !base.dnsServers.isEmpty {
            settings.dnsSettings = NEDNSSettings(servers: base.dnsServers)
        }
        return settings
    }

    deinit {
        refreshTask?.cancel()
    }
}
