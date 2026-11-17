import Foundation
import Network
import NetworkExtension

#if canImport(WireGuardKit)
import WireGuardKit
#endif

/// Network Extension entry point for OmniWARP.
///
/// The class intentionally keeps all AmneziaWG/WARP values behind the
/// `ConfigurationSnapshot` `Data` boundary. The concrete AWG/WARP models are
/// owned by other targets; the extension only needs UTF-8 wg-quick text to
/// construct the WireGuardKit runtime configuration.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private enum ProviderError: LocalizedError {
        case missingSnapshot
        case invalidSnapshot(Error)
        case invalidWarpConfig
        case coreUnavailable

        var errorDescription: String? {
            switch self {
            case .missingSnapshot:
                return "Configuration snapshot is missing from the tunnel configuration."
            case .invalidSnapshot(let error):
                return "Configuration snapshot could not be decoded: \(error.localizedDescription)"
            case .invalidWarpConfig:
                return "WARP configuration payload is not valid UTF-8 wg-quick text."
            case .coreUnavailable:
                return "AmneziaWG core is unavailable: WireGuardKit was not linked into the tunnel extension."
            }
        }
    }

    private enum MessageCommand: String {
        case stats
    }

    private struct StatsResponse: Encodable {
        var ok: Bool
        var receivedBytes: UInt64?
        var transmittedBytes: UInt64?
        var lastHandshake: TimeInterval?
        var error: String?

        static func success(receivedBytes: UInt64, transmittedBytes: UInt64, lastHandshake: TimeInterval?) -> StatsResponse {
            StatsResponse(
                ok: true,
                receivedBytes: receivedBytes,
                transmittedBytes: transmittedBytes,
                lastHandshake: lastHandshake,
                error: nil
            )
        }

        static func failure(_ error: String) -> StatsResponse {
            StatsResponse(ok: false, receivedBytes: nil, transmittedBytes: nil, lastHandshake: nil, error: error)
        }
    }

    private var snapshot: ConfigurationSnapshot?
    private var splitController: SplitTunnelController?
    private var splitBaseSettings: SplitInterfaceSettings?

    #if canImport(WireGuardKit)
    private lazy var adapter = WireGuardAdapter(with: self) { [weak self] level, message in
        self?.log(level: level, message: message)
    }
    private var runtimeConfigurationLoaded = false
    #endif

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        do {
            let snapshot = try loadSnapshot(options: options)
            self.snapshot = snapshot
            NSLog("[OmniWARP] snapshot v%@, AWG=%@ bytes, WARP=%@ bytes, split=%@, dns=%@, lists=%ld",
                  String(snapshot.version),
                  String(snapshot.awgParamsData.count),
                  String(snapshot.warpConfigData.count),
                  snapshot.splitTunnelingEnabled ? "on" : "off",
                  snapshot.dnsServers.joined(separator: ","),
                  snapshot.domainLists.count)

            #if canImport(WireGuardKit)
            let tunnelConfiguration = try makeTunnelConfiguration(snapshot: snapshot)
            startWireGuardAdapter(
                snapshot: snapshot,
                configuration: tunnelConfiguration,
                completionHandler: completionHandler
            )
            #else
            completionHandler(ProviderError.coreUnavailable)
            #endif
        } catch {
            completionHandler(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        NSLog("[OmniWARP] tunnel stop requested, reason=%ld", reason.rawValue)
        splitController?.stopRefresh()
        splitController = nil
        splitBaseSettings = nil
        #if canImport(WireGuardKit)
        runtimeConfigurationLoaded = false
        adapter.stop { _ in
            completionHandler()
        }
        #else
        completionHandler()
        #endif
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        guard let completionHandler else { return }
        guard isStatsMessage(messageData) else {
            completionHandler(jsonResponse(.failure("unsupported command")))
            return
        }

        #if canImport(WireGuardKit)
        guard runtimeConfigurationLoaded else {
            completionHandler(jsonResponse(.failure("WireGuard runtime is not started")))
            return
        }
        adapter.getRuntimeConfiguration { [weak self] runtimeConfiguration in
            guard let self else { return }
            guard let runtimeConfiguration else {
                completionHandler(self.jsonResponse(.failure("WireGuard runtime configuration is unavailable")))
                return
            }
            let stats = Self.parseRuntimeStats(runtimeConfiguration)
            completionHandler(self.jsonResponse(.success(
                receivedBytes: stats.receivedBytes,
                transmittedBytes: stats.transmittedBytes,
                lastHandshake: stats.lastHandshake
            )))
        }
        #else
        completionHandler(jsonResponse(.failure(ProviderError.coreUnavailable.localizedDescription)))
        #endif
    }

    // MARK: - Configuration boundary

    private func loadSnapshot(options: [String: NSObject]?) throws -> ConfigurationSnapshot {
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        let rawSnapshot =
            options?[ConfigurationSnapshot.providerConfigurationKey] as? Data ??
            (options?[ConfigurationSnapshot.providerConfigurationKey] as? String).flatMap { Data($0.utf8) } ??
            providerConfiguration?[ConfigurationSnapshot.providerConfigurationKey] as? Data ??
            (providerConfiguration?[ConfigurationSnapshot.providerConfigurationKey] as? String).flatMap { Data($0.utf8) }

        guard let rawSnapshot else {
            throw ProviderError.missingSnapshot
        }
        do {
            // Cross-process contract: TunnelManager stores JSONEncoder Data under
            // `configurationSnapshot`; do not use PropertyListDecoder here.
            return try ConfigurationSnapshot(jsonData: rawSnapshot)
        } catch {
            throw ProviderError.invalidSnapshot(error)
        }
    }

    // MARK: - Stats IPC

    private func isStatsMessage(_ data: Data) -> Bool {
        guard
            let object = try? JSONSerialization.jsonObject(with: data),
            let dictionary = object as? [String: Any]
        else { return false }
        return (dictionary["command"] as? String) == MessageCommand.stats.rawValue ||
            (dictionary["request"] as? String) == MessageCommand.stats.rawValue
    }

    private func jsonResponse(_ response: StatsResponse) -> Data? {
        try? JSONEncoder().encode(response)
    }

    #if canImport(WireGuardKit)
    private func makeTunnelConfiguration(snapshot: ConfigurationSnapshot) throws -> TunnelConfiguration {
        guard let wgQuickConfig = String(data: snapshot.warpConfigData, encoding: .utf8),
              !wgQuickConfig.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            throw ProviderError.invalidWarpConfig
        }
        let configuration = try OmniWARPWgQuickParser.parse(wgQuickConfig)
        if !snapshot.dnsServers.isEmpty {
            configuration.interface.dns = snapshot.dnsServers.compactMap(DNSServer.init(from:))
        }
        return configuration
    }

    private func startWireGuardAdapter(
        snapshot: ConfigurationSnapshot,
        configuration: TunnelConfiguration,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let enabledDescriptors = snapshot.domainLists.filter(\.enabled)
        guard snapshot.splitTunnelingEnabled, !enabledDescriptors.isEmpty else {
            adapter.start(tunnelConfiguration: configuration) { [weak self] adapterError in
                self?.handleAdapterStartResult(
                    adapterError,
                    splitRoutes: nil,
                    completionHandler: completionHandler
                )
            }
            return
        }

        let controller = SplitTunnelController(dnsServers: snapshot.dnsServers)
        let base = makeSplitInterfaceSettings(configuration: configuration)
        splitController = controller
        splitBaseSettings = base

        Task { [weak self] in
            guard let self else { return }
            do {
                let routes = try await controller.prepare(descriptors: snapshot.domainLists)
                self.adapter.start(tunnelConfiguration: configuration) { [weak self] adapterError in
                    self?.handleAdapterStartResult(
                        adapterError,
                        splitRoutes: routes,
                        completionHandler: completionHandler
                    )
                }
            } catch {
                NSLog("[OmniWARP][split] prepare failed: %@", error.localizedDescription)
                self.splitController = nil
                self.splitBaseSettings = nil
                completionHandler(error)
            }
        }
    }

    private func handleAdapterStartResult(
        _ adapterError: WireGuardAdapterError?,
        splitRoutes: RouteSnapshot?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        if let adapterError {
            NSLog("[OmniWARP] WireGuardAdapter start failed: %@", String(describing: adapterError))
            completionHandler(adapterError)
            return
        }
        runtimeConfigurationLoaded = true
        NSLog("[OmniWARP] WireGuardAdapter started, interface=%@", adapter.interfaceName ?? "unknown")

        guard let splitRoutes,
              let controller = splitController,
              let base = splitBaseSettings
        else {
            completionHandler(nil)
            return
        }

        Task { [weak self] in
            guard let self else { return }
            do {
                try await controller.apply(routes: splitRoutes, to: self, base: base)
                controller.startRefresh(provider: self, base: base)
                NSLog("[OmniWARP][split] exact routes applied: %ld", splitRoutes.routes.count)
                completionHandler(nil)
            } catch {
                NSLog("[OmniWARP][split] apply failed: %@", error.localizedDescription)
                controller.stopRefresh()
                self.adapter.stop { [weak self] _ in
                    self?.runtimeConfigurationLoaded = false
                    self?.splitController = nil
                    self?.splitBaseSettings = nil
                    completionHandler(error)
                }
            }
        }
    }

    private func makeSplitInterfaceSettings(configuration: TunnelConfiguration) -> SplitInterfaceSettings {
        let remoteAddress = configuration.peers.lazy.compactMap { peer -> String? in
            guard let host = peer.endpoint?.host else { return nil }
            switch host {
            case .ipv4(let address): return address.debugDescription
            case .ipv6(let address): return address.debugDescription
            case .name(let name, _): return name
            @unknown default: return nil
            }
        }.first ?? "0.0.0.0"

        var ipv4Addresses: [(address: String, subnetMask: String)] = []
        var ipv6Addresses: [(address: String, prefixLength: UInt8)] = []
        for range in configuration.interface.addresses {
            if let address = range.address as? IPv4Address {
                ipv4Addresses.append((address.debugDescription, range.subnetMask().debugDescription))
            } else if let address = range.address as? IPv6Address {
                ipv6Addresses.append((address.debugDescription, range.networkPrefixLength))
            }
        }

        return SplitInterfaceSettings(
            remoteAddress: remoteAddress,
            ipv4Addresses: ipv4Addresses,
            ipv6Addresses: ipv6Addresses,
            dnsServers: configuration.interface.dns.map(\.stringRepresentation),
            mtu: configuration.interface.mtu.map(Int.init) ?? 1280
        )
    }

    private static func parseRuntimeStats(_ runtimeConfiguration: String) -> (
        receivedBytes: UInt64,
        transmittedBytes: UInt64,
        lastHandshake: TimeInterval?
    ) {
        var receivedBytes: UInt64 = 0
        var transmittedBytes: UInt64 = 0
        var lastHandshake: TimeInterval?

        for line in runtimeConfiguration.split(separator: "\n") {
            if let value = line.split(separator: "=").last.map(String.init), line.hasPrefix("rx_bytes=") {
                receivedBytes += UInt64(value) ?? 0
            } else if let value = line.split(separator: "=").last.map(String.init), line.hasPrefix("tx_bytes=") {
                transmittedBytes += UInt64(value) ?? 0
            } else if line.hasPrefix("last_handshake_time_sec="),
                      let seconds = TimeInterval(line.dropFirst("last_handshake_time_sec=".count)),
                      seconds > 0 {
                lastHandshake = max(lastHandshake ?? 0, seconds)
            }
        }

        return (receivedBytes, transmittedBytes, lastHandshake)
    }

    private func log(level: WireGuardLogLevel, message: String) {
        switch level {
        case .verbose:
            NSLog("[OmniWARP][wg] %@", message)
        case .error:
            NSLog("[OmniWARP][wg:error] %@", message)
        }
    }
    #endif
}

#if canImport(WireGuardKit)
/// Minimal wg-quick bridge for the WireGuardKit SPM product.
///
/// Upstream ships its full parser in `Sources/Shared/Model`, outside the
/// WireGuardKit package target, so that initializer is not visible here. This
/// parser covers the standard fields and the AmneziaWG extensions used by the
/// Data boundary. It never logs configuration values (they contain keys).
private enum OmniWARPWgQuickParser {
    private enum Section {
        case none
        case interface
        case peer
    }

    private struct ParseError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    static func parse(_ text: String) throws -> TunnelConfiguration {
        var section = Section.none
        var interfaceAttributes: [String: String]?
        var peerAttributes: [String: String] = [:]
        var peers: [PeerConfiguration] = []

        for rawLine in text.components(separatedBy: .newlines) {
            let withoutComment = rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? ""
            let line = withoutComment.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty { continue }

            switch line.lowercased() {
            case "[interface]":
                if case .peer = section {
                    peers.append(try makePeer(from: peerAttributes))
                }
                guard interfaceAttributes == nil else {
                    throw ParseError(message: "wg-quick contains multiple [Interface] sections")
                }
                interfaceAttributes = [:]
                peerAttributes = [:]
                section = .interface
                continue
            case "[peer]":
                guard interfaceAttributes != nil else {
                    throw ParseError(message: "wg-quick [Peer] appears before [Interface]")
                }
                if case .peer = section {
                    peers.append(try makePeer(from: peerAttributes))
                }
                peerAttributes = [:]
                section = .peer
                continue
            default:
                break
            }

            guard let equals = line.firstIndex(of: "=") else {
                throw ParseError(message: "wg-quick line has no '=' separator")
            }
            let key = line[..<equals].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespacesAndNewlines)
            guard !key.isEmpty else {
                throw ParseError(message: "wg-quick contains an empty key")
            }

            switch section {
            case .none:
                throw ParseError(message: "wg-quick attributes must be inside [Interface] or [Peer]")
            case .interface:
                guard var attributes = interfaceAttributes else {
                    throw ParseError(message: "wg-quick interface state is invalid")
                }
                try merge(key: key, value: value, into: &attributes)
                interfaceAttributes = attributes
            case .peer:
                try merge(key: key, value: value, into: &peerAttributes)
            }
        }

        if case .peer = section {
            peers.append(try makePeer(from: peerAttributes))
        }
        guard let interfaceAttributes else {
            throw ParseError(message: "wg-quick has no [Interface] section")
        }
        let interface = try makeInterface(from: interfaceAttributes)
        let publicKeys = peers.map(\.publicKey)
        guard Set(publicKeys).count == publicKeys.count else {
            throw ParseError(message: "wg-quick contains duplicate peer public keys")
        }
        return TunnelConfiguration(name: "OmniWARP", interface: interface, peers: peers)
    }

    private static func merge(key: String, value: String, into attributes: inout [String: String]) throws {
        if let previous = attributes[key] {
            let repeatableKeys: Set<String> = ["address", "allowedips", "allowed_ip", "dns"]
            guard repeatableKeys.contains(key) else {
                throw ParseError(message: "wg-quick key is repeated: \(key)")
            }
            attributes[key] = previous + "," + value
        } else {
            attributes[key] = value
        }
    }

    private static func makeInterface(from attributes: [String: String]) throws -> InterfaceConfiguration {
        guard let privateKeyString = attributes["privatekey"] ?? attributes["private_key"],
              let privateKey = PrivateKey(base64Key: privateKeyString) ?? PrivateKey(hexKey: privateKeyString)
        else {
            throw ParseError(message: "wg-quick Interface.PrivateKey is missing or invalid")
        }
        var interface = InterfaceConfiguration(privateKey: privateKey)

        for (key, value) in attributes {
            switch key {
            case "privatekey", "private_key":
                continue
            case "listenport", "listen_port":
                interface.listenPort = try uint16(value, key: key)
            case "address":
                interface.addresses = try ipRanges(value, key: key)
            case "dns":
                for item in commaSeparated(value) {
                    if let server = DNSServer(from: item) {
                        interface.dns.append(server)
                    } else {
                        interface.dnsSearch.append(item)
                    }
                }
            case "mtu":
                interface.mtu = try uint16(value, key: key)
            case "jc":
                interface.junkPacketCount = try uint16(value, key: key)
            case "jmin":
                interface.junkPacketMinSize = try uint16(value, key: key)
            case "jmax":
                interface.junkPacketMaxSize = try uint16(value, key: key)
            case "s1":
                interface.initPacketJunkSize = try uint16(value, key: key)
            case "s2":
                interface.responsePacketJunkSize = try uint16(value, key: key)
            case "s3":
                interface.cookieReplyPacketJunkSize = try uint16(value, key: key)
            case "s4":
                interface.transportPacketJunkSize = try uint16(value, key: key)
            case "h1":
                interface.initPacketMagicHeader = value
            case "h2":
                interface.responsePacketMagicHeader = value
            case "h3":
                interface.underloadPacketMagicHeader = value
            case "h4":
                interface.transportPacketMagicHeader = value
            case "i1":
                interface.specialJunk1 = value
            case "i2":
                interface.specialJunk2 = value
            case "i3":
                interface.specialJunk3 = value
            case "i4":
                interface.specialJunk4 = value
            case "i5":
                interface.specialJunk5 = value
            case "headerprotectionkey":
                guard let keyValue = PrivateKey(base64Key: value) ?? PrivateKey(hexKey: value) else {
                    throw ParseError(message: "wg-quick Interface.HeaderProtectionKey is invalid")
                }
                interface.headerProtectionKey = keyValue
            case "contentpaddingaddition":
                interface.contentPaddingAddition = value
            case "rekeyaftertime":
                interface.rekeyAfterTime = value
            case "rekeytimeout":
                interface.rekeyTimeout = value
            case "rejectaftertime":
                interface.rejectAfterTime = value
            case "keepalivetimeout":
                interface.keepaliveTimeout = value
            case "maxhandshakeattempts":
                interface.maxHandshakeAttempts = value
            case "randomtrailers":
                interface.randomTrailers = value
            case "disablecookies":
                interface.disableCookies = value
            default:
                throw ParseError(message: "Unsupported wg-quick Interface key: \(key)")
            }
        }
        return interface
    }

    private static func makePeer(from attributes: [String: String]) throws -> PeerConfiguration {
        guard let publicKeyString = attributes["publickey"] ?? attributes["public_key"],
              let publicKey = PublicKey(base64Key: publicKeyString) ?? PublicKey(hexKey: publicKeyString)
        else {
            throw ParseError(message: "wg-quick Peer.PublicKey is missing or invalid")
        }
        var peer = PeerConfiguration(publicKey: publicKey)

        for (key, value) in attributes {
            switch key {
            case "publickey", "public_key":
                continue
            case "presharedkey", "preshared_key":
                guard let preSharedKey = PreSharedKey(base64Key: value) ?? PreSharedKey(hexKey: value) else {
                    throw ParseError(message: "wg-quick Peer.PresharedKey is invalid")
                }
                peer.preSharedKey = preSharedKey
            case "allowedips", "allowed_ip":
                peer.allowedIPs = try ipRanges(value, key: key)
            case "endpoint":
                guard let endpoint = Endpoint(from: value) else {
                    throw ParseError(message: "wg-quick Peer.Endpoint is invalid")
                }
                peer.endpoint = endpoint
            case "persistentkeepalive", "persistent_keepalive", "persistent_keepalive_interval":
                peer.persistentKeepAlive = value
            default:
                throw ParseError(message: "Unsupported wg-quick Peer key: \(key)")
            }
        }
        return peer
    }

    private static func commaSeparated(_ value: String) -> [String] {
        value.split(separator: ",", omittingEmptySubsequences: true).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    private static func ipRanges(_ value: String, key: String) throws -> [IPAddressRange] {
        try commaSeparated(value).map { item in
            guard let range = IPAddressRange(from: item) else {
                throw ParseError(message: "wg-quick \(key) contains an invalid IP range")
            }
            return range
        }
    }

    private static func uint16(_ value: String, key: String) throws -> UInt16 {
        guard let number = UInt16(value) else {
            throw ParseError(message: "wg-quick \(key) is not a UInt16")
        }
        return number
    }
}
#endif
