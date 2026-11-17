import Foundation

/// Stable, property-list-safe identity of a remote domain list.
///
/// Only descriptors whose `enabled` flag is `true` should be placed in
/// `ConfigurationSnapshot.domainLists` when creating a tunnel configuration.
public struct DomainListDescriptor: Codable, Hashable, Sendable {
    public var id: String
    public var url: URL
    public var enabled: Bool
    public var name: String?

    public init(id: String, url: URL, enabled: Bool = true, name: String? = nil) {
        self.id = id
        self.url = url
        self.enabled = enabled
        self.name = name
    }
}

public enum ConfigurationSnapshotError: Error, Equatable {
    case unsupportedVersion(Int)
    case invalidPropertyListRoot
}

/// The single configuration boundary between the app and the Network Extension.
///
/// `awgParamsData` and `warpConfigData` deliberately remain opaque `Data` here:
/// this type does not depend on the concrete AWG/WARP model implementations.
/// The tunnel-side WireGuardKit bridge currently expects `warpConfigData` to be
/// UTF-8 wg-quick text (including AmneziaWG keys), while `awgParamsData` is an
/// app-owned JSON payload retained for diagnostics and future migrations.
public struct ConfigurationSnapshot: Codable, Hashable, Sendable {
    public static let currentVersion = 1
    public static let providerConfigurationKey = "configurationSnapshot"

    public var version: Int
    public var awgParamsData: Data
    public var warpConfigData: Data
    public var domainLists: [DomainListDescriptor]
    public var splitTunnelingEnabled: Bool
    public var dnsServers: [String]

    public init(
        version: Int = ConfigurationSnapshot.currentVersion,
        awgParamsData: Data = Data(),
        warpConfigData: Data = Data(),
        domainLists: [DomainListDescriptor] = [],
        splitTunnelingEnabled: Bool = false,
        dnsServers: [String] = []
    ) {
        self.version = version
        self.awgParamsData = awgParamsData
        self.warpConfigData = warpConfigData
        self.domainLists = domainLists
        self.splitTunnelingEnabled = splitTunnelingEnabled
        self.dnsServers = dnsServers
    }

    private enum CodingKeys: String, CodingKey {
        case version
        case awgParamsData
        case warpConfigData
        case domainLists
        case splitTunnelingEnabled
        case dnsServers
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decodeIfPresent(Int.self, forKey: .version) ?? Self.currentVersion
        guard version == Self.currentVersion else {
            throw ConfigurationSnapshotError.unsupportedVersion(version)
        }

        self.init(
            version: version,
            awgParamsData: try container.decode(Data.self, forKey: .awgParamsData),
            warpConfigData: try container.decode(Data.self, forKey: .warpConfigData),
            domainLists: try container.decodeIfPresent([DomainListDescriptor].self, forKey: .domainLists) ?? [],
            splitTunnelingEnabled: try container.decodeIfPresent(Bool.self, forKey: .splitTunnelingEnabled) ?? false,
            dnsServers: try container.decodeIfPresent([String].self, forKey: .dnsServers) ?? []
        )
    }

    /// JSON is used inside `NETunnelProviderProtocol.providerConfiguration`.
    public func jsonData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }

    public init(jsonData: Data) throws {
        self = try JSONDecoder().decode(Self.self, from: jsonData)
    }

    /// Binary/XML property-list serialization is also supported for persistence
    /// and for callers that need Foundation property-list objects.
    public func propertyListData(
        format: PropertyListSerialization.PropertyListFormat = .binary
    ) throws -> Data {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = format
        return try encoder.encode(self)
    }

    public init(propertyListData: Data) throws {
        self = try PropertyListDecoder().decode(Self.self, from: propertyListData)
    }

    public func propertyListObject() throws -> [String: Any] {
        let data = try propertyListData(format: .binary)
        let object = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dictionary = object as? [String: Any] else {
            throw ConfigurationSnapshotError.invalidPropertyListRoot
        }
        return dictionary
    }

    public init(propertyListObject: [String: Any]) throws {
        let data = try PropertyListSerialization.data(
            fromPropertyList: propertyListObject,
            format: .binary,
            options: 0
        )
        try self.init(propertyListData: data)
    }
}
