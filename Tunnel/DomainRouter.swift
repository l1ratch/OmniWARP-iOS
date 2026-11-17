import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Network

public enum DomainRoute: String, Sendable {
    case warp
    case direct
}

public struct DomainListSource: Hashable, Sendable {
    public let id: String
    public let url: URL

    public init(id: String, url: URL) {
        self.id = id
        self.url = url
    }
}

public struct DomainSnapshot: Sendable, Equatable {
    public let rules: [DomainRule]
    public let revision: UInt64
    public let loadedAt: Date

    public init(rules: [DomainRule], revision: UInt64, loadedAt: Date) {
        self.rules = rules
        self.revision = revision
        self.loadedAt = loadedAt
    }

    public func contains(_ host: String) -> Bool {
        DomainList.contains(host, in: rules)
    }

    public func route(for host: String) -> DomainRoute {
        contains(host) ? .warp : .direct
    }
}

public enum IPAddressFamily: String, Sendable, CaseIterable {
    case ipv4
    case ipv6

    public var prefixLength: UInt8 {
        switch self {
        case .ipv4: return 32
        case .ipv6: return 128
        }
    }

    public var dnsRecordType: UInt16 {
        switch self {
        case .ipv4: return 1
        case .ipv6: return 28
        }
    }
}

public struct ResolvedAddress: Hashable, Sendable {
    public let address: String
    public let family: IPAddressFamily
    public let timeToLive: UInt32
    public let sourceDomain: String

    public init(address: String, timeToLive: UInt32, sourceDomain: String) throws {
        let family: IPAddressFamily
        if IPv4Address(address) != nil {
            family = .ipv4
        } else if IPv6Address(address) != nil {
            family = .ipv6
        } else {
            throw DomainRouterError.invalidIPAddress(address)
        }

        self.address = address
        self.family = family
        self.timeToLive = min(max(timeToLive, 1), 86_400)
        self.sourceDomain = try DomainList.normalize(sourceDomain)
    }
}

/// One exact host route. No subnet aggregation is performed.
public struct IPRoute: Hashable, Sendable {
    public let address: String
    public let prefixLength: UInt8
    public let sourceDomains: [String]
    public let expiresAt: Date

    public init(address: String, prefixLength: UInt8, sourceDomains: [String], expiresAt: Date) {
        self.address = address
        self.prefixLength = prefixLength
        self.sourceDomains = sourceDomains
        self.expiresAt = expiresAt
    }

    public var cidr: String {
        "\(address)/\(prefixLength)"
    }
}

/// Immutable snapshot suitable for constructing NE includedRoutes/AllowedIPs.
public struct RouteSnapshot: Sendable, Equatable {
    public let routes: [IPRoute]
    public let revision: UInt64
    public let updatedAt: Date

    public init(routes: [IPRoute], revision: UInt64, updatedAt: Date) {
        self.routes = routes
        self.revision = revision
        self.updatedAt = updatedAt
    }

    public static let empty = RouteSnapshot(routes: [], revision: 0, updatedAt: Date(timeIntervalSince1970: 0))

    public var includedRouteCIDRs: [String] {
        routes.map(\.cidr)
    }

    public func contains(address: String) -> Bool {
        routes.contains { $0.address == address }
    }
}

public enum DomainRouterError: Error, Equatable, Sendable {
    case invalidSource(String)
    case unsupportedURLScheme(String)
    case httpStatus(Int)
    case responseTooLarge
    case invalidUTF8
    case emptyDomainList
    case sourceUnavailable(String)
    case requestTimeout
    case invalidIPAddress(String)
}

public protocol DomainAddressResolver: Sendable {
    func resolve(domain: String, family: IPAddressFamily) async throws -> [ResolvedAddress]
}

/// Actor-owned mutable state; consumers only receive immutable snapshots.
public actor DomainRouter {
    private struct ObservedResolution: Sendable {
        var addresses: [String: Date]
        var updatedAt: Date
    }

    private struct SourceFetchOutcome: Sendable {
        let index: Int
        let body: String?
        let error: String?
    }

    private struct RouteRefreshOutcome: Sendable {
        let domain: String
        let addresses: [ResolvedAddress]?
        let error: String?
    }

    private static let maximumTrackedDomains = 2_048

    private var domainSnapshotStorage: DomainSnapshot
    private var lastKnownGoodSnapshot: DomainSnapshot
    private var cachedListBodies: [String: String]
    private var observed: [String: ObservedResolution] = [:]
    private var routeSnapshotStorage: RouteSnapshot = .empty

    public private(set) var lastRefreshWarnings: [String] = []
    public private(set) var lastRouteRefreshWarnings: [String] = []

    public init(initialRules: [DomainRule] = [], cachedLists: [String: String] = [:]) {
        let cachedRules = cachedLists.values.sorted().flatMap { DomainList.parse($0) }
        let rules = initialRules.isEmpty ? cachedRules : initialRules
        var unique: Set<DomainRule> = []
        let deduplicated = rules.filter { unique.insert($0).inserted }
        let snapshot = DomainSnapshot(rules: deduplicated, revision: 0, loadedAt: Date())
        self.domainSnapshotStorage = snapshot
        self.lastKnownGoodSnapshot = snapshot
        self.cachedListBodies = cachedLists
    }

    public static func make(domainListText: String) -> DomainRouter {
        DomainRouter(initialRules: DomainList.parse(domainListText))
    }

    public var snapshot: DomainSnapshot {
        domainSnapshotStorage
    }

    /// Integration-facing immutable snapshot shared across DNS and SNI policy.
    public var sharedSnapshot: DomainSnapshot {
        domainSnapshotStorage
    }

    public var lastKnownGood: DomainSnapshot {
        lastKnownGoodSnapshot
    }

    public var cachedLists: [String: String] {
        cachedListBodies
    }

    public func contains(_ domain: String) -> Bool {
        domainSnapshotStorage.contains(domain)
    }

    public func route(for domain: String) -> DomainRoute {
        domainSnapshotStorage.route(for: domain)
    }

    public func updateRules(with text: String, now: Date = Date()) throws -> DomainSnapshot {
        let parsed = DomainList.parseDetailed(text)
        guard !parsed.rules.isEmpty else {
            throw DomainRouterError.emptyDomainList
        }
        return installRules(parsed.rules, now: now)
    }

    /// Refreshes all sources with at most `maxConcurrentLoads` requests. A failed
    /// source falls back to its last cached body. If neither network nor cache
    /// can provide a source, the current last-known-good snapshot is retained.
    @discardableResult
    public func refresh(
        sources: [DomainListSource],
        session: URLSession = .shared,
        timeout: TimeInterval = 15,
        maxConcurrentLoads: Int = 4,
        now: Date = Date()
    ) async throws -> DomainSnapshot {
        guard Set(sources.map(\.id)).count == sources.count else {
            throw DomainRouterError.invalidSource("Duplicate source id")
        }
        for source in sources {
            let scheme = source.url.scheme?.lowercased()
            guard scheme == "http" || scheme == "https" else {
                throw DomainRouterError.unsupportedURLScheme(source.url.absoluteString)
            }
        }

        let outcomes = await Self.loadSources(
            sources,
            session: session,
            timeout: timeout,
            maxConcurrentLoads: maxConcurrentLoads
        )

        var bodies: [String] = []
        var newCache = cachedListBodies
        var warnings: [String] = []

        for (index, source) in sources.enumerated() {
            let outcome = outcomes[index]
            if let body = outcome.body {
                guard !DomainList.parse(body).isEmpty else {
                    throw DomainRouterError.emptyDomainList
                }
                bodies.append(body)
                newCache[source.id] = body
            } else if let cached = cachedListBodies[source.id] {
                bodies.append(cached)
                warnings.append("\(source.id): \(outcome.error ?? "unavailable"); using last-known-good cache")
            } else {
                throw DomainRouterError.sourceUnavailable("\(source.id): \(outcome.error ?? "unavailable")")
            }
        }

        let rules = DomainList.parse(bodies.joined(separator: "\n"))
        guard !rules.isEmpty else {
            throw DomainRouterError.emptyDomainList
        }

        cachedListBodies = newCache
        lastRefreshWarnings = warnings
        return installRules(rules, now: now)
    }

    /// Records only real A/AAAA answers. FakeIP addresses are not special-cased
    /// and must never be fed to this method by a packet tunnel.
    @discardableResult
    public func recordResolution(
        domain: String,
        addresses: [ResolvedAddress],
        family: IPAddressFamily? = nil,
        now: Date = Date()
    ) throws -> RouteSnapshot {
        let normalized = try DomainList.normalize(domain)
        guard contains(normalized) else {
            return rebuildRouteSnapshot(now: now)
        }

        // A and AAAA responses arrive independently. Replace only the family
        // carried by this response, preserving the other family's live TTLs.
        var expirations: [String: Date] = [:]
        if let family {
            expirations = observed[normalized]?.addresses.filter { address, _ in
                let existingFamily: IPAddressFamily = IPv4Address(address) != nil ? .ipv4 : .ipv6
                return existingFamily != family
            } ?? [:]
        }

        if addresses.isEmpty {
            if expirations.isEmpty {
                observed.removeValue(forKey: normalized)
            } else {
                observed[normalized]?.addresses = expirations
                observed[normalized]?.updatedAt = now
            }
            return rebuildRouteSnapshot(now: now)
        }

        if observed[normalized] == nil && observed.count >= Self.maximumTrackedDomains {
            if let oldest = observed.min(by: { $0.value.updatedAt < $1.value.updatedAt })?.key {
                observed.removeValue(forKey: oldest)
                expirations = [:]
            }
        }

        for resolved in addresses {
            let validated = try ResolvedAddress(
                address: resolved.address,
                timeToLive: resolved.timeToLive,
                sourceDomain: normalized
            )
            guard family == nil || validated.family == family else { continue }
            let expiration = now.addingTimeInterval(TimeInterval(validated.timeToLive))
            expirations[validated.address] = max(
                expirations[validated.address] ?? .distantPast,
                expiration
            )
        }
        observed[normalized] = ObservedResolution(addresses: expirations, updatedAt: now)
        return rebuildRouteSnapshot(now: now)
    }

    public func removeResolution(domain: String, now: Date = Date()) -> RouteSnapshot {
        if let normalized = try? DomainList.normalize(domain) {
            observed.removeValue(forKey: normalized)
        }
        return rebuildRouteSnapshot(now: now)
    }

    public func routeSnapshot(now: Date = Date()) -> RouteSnapshot {
        rebuildRouteSnapshot(now: now)
    }

    public var currentRouteSnapshot: RouteSnapshot {
        routeSnapshotStorage
    }

    public func domainsNeedingRefresh(now: Date = Date(), refreshBeforeExpiration: TimeInterval = 60) -> [String] {
        observed.compactMap { domain, resolution in
            guard let expiration = resolution.addresses.values.min() else { return nil }
            return expiration.timeIntervalSince(now) <= refreshBeforeExpiration ? domain : nil
        }.sorted()
    }

    /// Re-resolves already observed domains with bounded concurrency. Failed
    /// refreshes leave the previous routes in place until their original TTL.
    @discardableResult
    public func refreshResolvedRoutes(
        using resolver: any DomainAddressResolver,
        now: Date = Date(),
        onlyDue: Bool = true,
        maxConcurrentResolutions: Int = 4
    ) async -> RouteSnapshot {
        let domains: [String]
        if onlyDue {
            domains = domainsNeedingRefresh(now: now)
        } else {
            domains = observed.keys.sorted()
        }
        guard !domains.isEmpty else {
            return rebuildRouteSnapshot(now: now)
        }

        let outcomes = await Self.refreshDomains(
            domains,
            resolver: resolver,
            maxConcurrentResolutions: maxConcurrentResolutions
        )
        var warnings: [String] = []
        for outcome in outcomes {
            if let addresses = outcome.addresses {
                try? recordResolution(domain: outcome.domain, addresses: addresses, now: now)
            } else {
                warnings.append("\(outcome.domain): \(outcome.error ?? "resolution failed")")
            }
        }
        lastRouteRefreshWarnings = warnings
        return rebuildRouteSnapshot(now: now)
    }

    /// Long-running cooperative loop for dynamic route updates without a tunnel
    /// restart. Cancel the surrounding Task to stop it.
    public func runRouteRefreshLoop(
        using resolver: any DomainAddressResolver,
        interval: TimeInterval = 30,
        onSnapshot: @escaping @Sendable (RouteSnapshot) -> Void
    ) async {
        let delaySeconds = interval.isFinite ? min(max(interval, 1), 3_600) : 30
        let delay = UInt64(delaySeconds * 1_000_000_000)
        while !Task.isCancelled {
            let updated = await refreshResolvedRoutes(using: resolver, onlyDue: true)
            if !Task.isCancelled {
                onSnapshot(updated)
            }
            do {
                try await Task.sleep(nanoseconds: delay)
            } catch {
                return
            }
        }
    }

    private func installRules(_ rules: [DomainRule], now: Date) -> DomainSnapshot {
        var unique: Set<DomainRule> = []
        let deduplicated = rules.filter { unique.insert($0).inserted }
        let next = DomainSnapshot(
            rules: deduplicated,
            revision: domainSnapshotStorage.revision &+ 1,
            loadedAt: now
        )
        domainSnapshotStorage = next
        lastKnownGoodSnapshot = next

        // Domains which are no longer routed must not leave stale host routes.
        observed = observed.filter { next.contains($0.key) }
        _ = rebuildRouteSnapshot(now: now)
        return next
    }

    @discardableResult
    private func rebuildRouteSnapshot(now: Date) -> RouteSnapshot {
        observed = observed.compactMapValues { resolution in
            let liveAddresses = resolution.addresses.filter { $0.value > now }
            guard !liveAddresses.isEmpty else { return nil }
            return ObservedResolution(addresses: liveAddresses, updatedAt: resolution.updatedAt)
        }

        struct Accumulator {
            var expiration: Date
            var domains: Set<String>
        }
        var grouped: [String: Accumulator] = [:]
        for (domain, resolution) in observed {
            for (address, expiration) in resolution.addresses {
                var value = grouped[address] ?? Accumulator(expiration: expiration, domains: [])
                value.expiration = max(value.expiration, expiration)
                value.domains.insert(domain)
                grouped[address] = value
            }
        }

        let routes = grouped.compactMap { address, value -> IPRoute? in
            let family: IPAddressFamily
            if IPv4Address(address) != nil {
                family = .ipv4
            } else if IPv6Address(address) != nil {
                family = .ipv6
            } else {
                return nil
            }
            return IPRoute(
                address: address,
                prefixLength: family.prefixLength,
                sourceDomains: value.domains.sorted(),
                expiresAt: value.expiration
            )
        }.sorted { $0.cidr < $1.cidr }

        let oldCIDRs = Set(routeSnapshotStorage.includedRouteCIDRs)
        let newCIDRs = Set(routes.map(\.cidr))
        let revision = oldCIDRs == newCIDRs
            ? routeSnapshotStorage.revision
            : routeSnapshotStorage.revision &+ 1
        routeSnapshotStorage = RouteSnapshot(routes: routes, revision: revision, updatedAt: now)
        return routeSnapshotStorage
    }

    private static func loadSources(
        _ sources: [DomainListSource],
        session: URLSession,
        timeout: TimeInterval,
        maxConcurrentLoads: Int
    ) async -> [SourceFetchOutcome] {
        guard !sources.isEmpty else { return [] }
        let limit = min(max(maxConcurrentLoads, 1), 16)
        var indexed = Array(repeating: SourceFetchOutcome(index: 0, body: nil, error: "not loaded"), count: sources.count)

        return await withTaskGroup(of: SourceFetchOutcome.self) { group in
            var nextIndex = 0
            for index in 0..<min(limit, sources.count) {
                nextIndex += 1
                let source = sources[index]
                group.addTask {
                    do {
                        let body = try await fetch(source: source, session: session, timeout: timeout)
                        return SourceFetchOutcome(index: index, body: body, error: nil)
                    } catch {
                        return SourceFetchOutcome(index: index, body: nil, error: String(describing: error))
                    }
                }
            }

            while let outcome = await group.next() {
                indexed[outcome.index] = outcome
                if nextIndex < sources.count {
                    let index = nextIndex
                    nextIndex += 1
                    let source = sources[index]
                    group.addTask {
                        do {
                            let body = try await fetch(source: source, session: session, timeout: timeout)
                            return SourceFetchOutcome(index: index, body: body, error: nil)
                        } catch {
                            return SourceFetchOutcome(index: index, body: nil, error: String(describing: error))
                        }
                    }
                }
            }
            return indexed
        }
    }

    private static func fetch(source: DomainListSource, session: URLSession, timeout: TimeInterval) async throws -> String {
        var request = URLRequest(url: source.url)
        let effectiveTimeout = timeout.isFinite ? min(max(timeout, 0.1), 3_600) : 15
        request.timeoutInterval = effectiveTimeout
        let data = try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask {
                let (data, response) = try await session.data(for: request)
                if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                    throw DomainRouterError.httpStatus(http.statusCode)
                }
                return data
            }
            group.addTask {
                let nanoseconds = UInt64(effectiveTimeout * 1_000_000_000)
                try await Task.sleep(nanoseconds: nanoseconds)
                throw DomainRouterError.requestTimeout
            }
            guard let first = try await group.next() else {
                throw DomainRouterError.sourceUnavailable(source.id)
            }
            group.cancelAll()
            return first
        }

        guard data.count <= 8 * 1_024 * 1_024 else {
            throw DomainRouterError.responseTooLarge
        }
        guard let body = String(data: data, encoding: .utf8) else {
            throw DomainRouterError.invalidUTF8
        }
        return body
    }

    private static func refreshDomains(
        _ domains: [String],
        resolver: any DomainAddressResolver,
        maxConcurrentResolutions: Int
    ) async -> [RouteRefreshOutcome] {
        let limit = min(max(maxConcurrentResolutions, 1), 16)
        var results: [RouteRefreshOutcome] = []
        results.reserveCapacity(domains.count)

        return await withTaskGroup(of: RouteRefreshOutcome.self) { group in
            var nextIndex = 0
            for domain in domains.prefix(limit) {
                nextIndex += 1
                group.addTask {
                    await refreshDomain(domain, resolver: resolver)
                }
            }
            while let result = await group.next() {
                results.append(result)
                if nextIndex < domains.count {
                    let domain = domains[nextIndex]
                    nextIndex += 1
                    group.addTask {
                        await refreshDomain(domain, resolver: resolver)
                    }
                }
            }
            return results
        }
    }

    private static func refreshDomain(_ domain: String, resolver: any DomainAddressResolver) async -> RouteRefreshOutcome {
        do {
            async let ipv4 = resolver.resolve(domain: domain, family: .ipv4)
            async let ipv6 = resolver.resolve(domain: domain, family: .ipv6)
            let ipv4Addresses = try await ipv4
            let ipv6Addresses = try await ipv6
            return RouteRefreshOutcome(domain: domain, addresses: ipv4Addresses + ipv6Addresses, error: nil)
        } catch {
            return RouteRefreshOutcome(domain: domain, addresses: nil, error: String(describing: error))
        }
    }
}
