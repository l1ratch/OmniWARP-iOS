import Foundation
import Network

/// Откуда взят endpoint. Метрики есть только у реально проверенных trace-запросов.
public enum EndpointSource: String, Codable, Sendable, Hashable {
    case anchor
    case random
    case fallback
}

/// Кандидат для последующего AWG handshake.
///
/// Важно: `rttMilliseconds`, `lossPercentage` и `httpsStatus` относятся к HTTP
/// trace всего IP, а не к UDP-порту. Одинаковые метрики у разных портов одного IP
/// не являются подтверждением UDP-доступности. Проверка WireGuard/AWG handshake
/// выполняется отдельным CandidateValidator.
public struct EndpointCandidate: Identifiable, Codable, Hashable, Sendable {
    public var ip: String
    public var port: UInt16
    public var colo: String?
    public var rttMilliseconds: Double?
    public var lossPercentage: Double?
    public var httpsStatus: Int?
    public var source: EndpointSource

    public var id: String { "\(ip):\(port)" }
    public var host: String { ip }
    public var rttMs: Double? {
        get { rttMilliseconds }
        set { rttMilliseconds = newValue }
    }
    public var httpsReachable: Bool {
        guard let httpsStatus else { return false }
        return (200..<300).contains(httpsStatus)
    }

    public init(
        ip: String,
        port: UInt16,
        colo: String? = nil,
        rttMilliseconds: Double? = nil,
        lossPercentage: Double? = nil,
        httpsStatus: Int? = nil,
        source: EndpointSource = .anchor
    ) {
        self.ip = ip
        self.port = port
        self.colo = colo
        self.rttMilliseconds = rttMilliseconds
        self.lossPercentage = lossPercentage
        self.httpsStatus = httpsStatus
        self.source = source
    }
}

/// Агрегированный результат нескольких настоящих HTTP `/cdn-cgi/trace` запросов.
/// `nil` у RTT/colo означает отсутствие измерения, а не нулевую задержку/пустой colo.
public struct TraceResult: Codable, Hashable, Sendable {
    public var ip: String
    public var colo: String?
    public var rttMilliseconds: Double?
    public var lossPercentage: Double
    public var httpsStatus: Int?
    public var warpEnabled: Bool?

    public init(
        ip: String,
        colo: String?,
        rttMilliseconds: Double?,
        lossPercentage: Double,
        httpsStatus: Int?,
        warpEnabled: Bool?
    ) {
        self.ip = ip
        self.colo = colo
        self.rttMilliseconds = rttMilliseconds
        self.lossPercentage = lossPercentage
        self.httpsStatus = httpsStatus
        self.warpEnabled = warpEnabled
    }
}

/// Сериализуемая конфигурация WARP + AmneziaWG.
///
/// Содержит приватный ключ. Не помещайте ни этот объект, ни результат
/// `wgQuickConfiguration()` в логи, analytics или crash attachments.
public struct WarpConfig: Codable, Sendable, Equatable {
    public var privateKey: String
    public var peerPublicKey: String
    public var addresses: [String]
    public var dns: [String]
    public var mtu: UInt16?
    public var endpoint: EndpointCandidate?
    public var amneziaWG: AmneziaWGParams
    public var allowedIPs: [String]
    public var persistentKeepalive: UInt16?

    public init(
        privateKey: String,
        peerPublicKey: String,
        addresses: [String],
        dns: [String] = ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
        mtu: UInt16? = 1280,
        endpoint: EndpointCandidate? = nil,
        amneziaWG: AmneziaWGParams = .zapretManager,
        allowedIPs: [String] = ["0.0.0.0/0", "::/0"],
        persistentKeepalive: UInt16? = 25
    ) {
        self.privateKey = privateKey
        self.peerPublicKey = peerPublicKey
        self.addresses = addresses
        self.dns = dns
        self.mtu = mtu
        self.endpoint = endpoint
        self.amneziaWG = amneziaWG
        self.allowedIPs = allowedIPs
        self.persistentKeepalive = persistentKeepalive
    }

    /// Возвращает копию с новым endpoint. Старые сетевые измерения намеренно
    /// сбрасываются, если изменился IP: переносить их на другой адрес нельзя.
    public func withEndpoint(host: String, port: UInt16) -> WarpConfig {
        var copy = self
        if endpoint?.ip == host {
            copy.endpoint?.port = port
        } else {
            copy.endpoint = EndpointCandidate(ip: host, port: port, source: .fallback)
        }
        return copy
    }

    public func withEndpoint(_ candidate: EndpointCandidate) -> WarpConfig {
        var copy = self
        copy.endpoint = candidate
        return copy
    }

    /// Единственный Data boundary между приложением и Network Extension.
    /// Результат — UTF-8 wg-quick/AmneziaWG текст для WireGuardKit parser.
    public func wgQuickData() throws -> Data {
        Data(try wgQuickConfiguration().utf8)
    }

    public func wgQuickConfiguration() throws -> String {
        try validate()

        var lines = [
            "[Interface]",
            "PrivateKey = \(privateKey)",
            "Address = \(addresses.joined(separator: ", "))"
        ]
        if !dns.isEmpty { lines.append("DNS = \(dns.joined(separator: ", "))") }
        if let mtu { lines.append("MTU = \(mtu)") }
        lines.append(contentsOf: [
            "Jc = \(amneziaWG.jc)",
            "Jmin = \(amneziaWG.jmin)",
            "Jmax = \(amneziaWG.jmax)",
            "S1 = \(amneziaWG.s1)",
            "S2 = \(amneziaWG.s2)",
            "H1 = \(amneziaWG.h1)",
            "H2 = \(amneziaWG.h2)",
            "H3 = \(amneziaWG.h3)",
            "H4 = \(amneziaWG.h4)",
            "I1 = <b 0x\(amneziaWG.i1)>",
            "",
            "[Peer]",
            "PublicKey = \(peerPublicKey)",
            "AllowedIPs = \(allowedIPs.joined(separator: ", "))"
        ])
        if let endpoint {
            lines.append("Endpoint = \(Self.endpointString(host: endpoint.host, port: endpoint.port))")
        }
        if let persistentKeepalive {
            lines.append("PersistentKeepalive = \(persistentKeepalive)")
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }

    private func validate() throws {
        guard Self.isWireGuardKey(privateKey), Self.isWireGuardKey(peerPublicKey) else {
            throw WarpConfigError.invalidKey
        }
        guard !addresses.isEmpty else { throw WarpConfigError.missingAddresses }
        for address in addresses where !Self.isValidAddress(address, allowCIDR: true) {
            throw WarpConfigError.invalidAddress
        }
        for server in dns where !Self.isValidAddress(server, allowCIDR: false) {
            throw WarpConfigError.invalidDNS
        }
        guard !allowedIPs.isEmpty else { throw WarpConfigError.missingAllowedIPs }
        for range in allowedIPs where !Self.isValidAddress(range, allowCIDR: true) {
            throw WarpConfigError.invalidAllowedIP
        }
        if let endpoint {
            guard endpoint.port > 0, Self.isValidEndpointHost(endpoint.host) else {
                throw WarpConfigError.invalidEndpoint
            }
        }
        _ = try amneziaWG.validated()
    }

    private static func isWireGuardKey(_ value: String) -> Bool {
        guard value.count == 44, !value.contains(where: { $0.isWhitespace }),
              let data = Data(base64Encoded: value) else { return false }
        return data.count == 32
    }

    private static func isValidAddress(_ value: String, allowCIDR: Bool) -> Bool {
        guard !value.isEmpty, !value.contains(where: { $0.isWhitespace }) else { return false }
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || (allowCIDR && parts.count == 2) else { return false }
        let address = String(parts[0])
        if address.contains(":") {
            guard IPv6Address(address) != nil else { return false }
            if parts.count == 2 { return UInt8(parts[1]).map { $0 <= 128 } == true }
            return true
        }
        guard IPv4Address(address) != nil else { return false }
        if parts.count == 2 { return UInt8(parts[1]).map { $0 <= 32 } == true }
        return true
    }

    private static func isValidEndpointHost(_ host: String) -> Bool {
        guard !host.isEmpty,
              !host.contains(where: { $0.isWhitespace || $0 == "/" || $0 == "[" || $0 == "]" }) else {
            return false
        }
        return true
    }

    private static func endpointString(host: String, port: UInt16) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}

public enum WarpConfigError: LocalizedError, Sendable {
    case invalidKey
    case missingAddresses
    case invalidAddress
    case invalidDNS
    case missingAllowedIPs
    case invalidAllowedIP
    case invalidEndpoint

    public var errorDescription: String? {
        switch self {
        case .invalidKey: return "Некорректный ключ WireGuard."
        case .missingAddresses: return "WARP не вернул адреса интерфейса."
        case .invalidAddress: return "Некорректный адрес интерфейса."
        case .invalidDNS: return "Некорректный адрес DNS-сервера."
        case .missingAllowedIPs: return "AllowedIPs не может быть пустым."
        case .invalidAllowedIP: return "Некорректная подсеть AllowedIPs."
        case .invalidEndpoint: return "Некорректный host или port endpoint."
        }
    }
}
