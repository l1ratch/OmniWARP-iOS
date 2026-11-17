import Foundation
import Observation
import Security

@MainActor
@Observable
final class WarpRegistrationViewModel {
    private(set) var config: WarpConfig?
    var isRegistering = false
    var lastError: String?
    var statusMessage: String?

    @ObservationIgnored
    private let service = "com.omniwarp.OmniWARP.warp-config"
    @ObservationIgnored
    private let account = "current"

    init() {
        config = Self.loadFromKeychain(service: service, account: account)
    }

    var isReady: Bool { config != nil }

    func register(amneziaWG: AmneziaWGParams, endpoint: EndpointCandidate?) async {
        guard !isRegistering else { return }
        isRegistering = true
        lastError = nil
        statusMessage = nil
        defer { isRegistering = false }

        do {
            let registered = try await WarpRegistrar().register(
                amneziaWG: amneziaWG,
                endpoint: endpoint ?? EndpointScout.fallbackCandidate,
                model: "iPhone",
                locale: Locale.current.identifier
            )
            _ = try registered.wgQuickData()
            try saveToKeychain(registered)
            config = registered
            statusMessage = "Ключи WARP получены. Приватный ключ не отображается в интерфейсе."
        } catch is CancellationError {
            statusMessage = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    func configuration(
        amneziaWG: AmneziaWGParams,
        endpoint: EndpointCandidate?
    ) throws -> WarpConfig {
        guard var config else { throw AppConfigurationError.missingWarpConfig }
        config.amneziaWG = amneziaWG
        if let endpoint {
            config = config.withEndpoint(endpoint)
        } else if config.endpoint == nil {
            config = config.withEndpoint(EndpointScout.fallbackCandidate)
        }
        _ = try config.wgQuickData()
        return config
    }

    /// Сохраняет результат автоподбора только после проверки сериализацией.
    func save(_ config: WarpConfig) throws {
        _ = try config.wgQuickData()
        try saveToKeychain(config)
        self.config = config
        lastError = nil
        statusMessage = "Проверенная конфигурация WARP сохранена в Keychain."
    }

    func report(error: Error) {
        lastError = error.localizedDescription
    }

    private func saveToKeychain(_ config: WarpConfig) throws {
        let data = try JSONEncoder().encode(config)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        if updateStatus == errSecItemNotFound {
            var attributes = query
            attributes[kSecValueData as String] = data
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let status = SecItemAdd(attributes as CFDictionary, nil)
            guard status == errSecSuccess else { throw WarpRegistrationStorageError.keychain(status) }
        } else if updateStatus != errSecSuccess {
            throw WarpRegistrationStorageError.keychain(updateStatus)
        }
    }

    private static func loadFromKeychain(service: String, account: String) -> WarpConfig? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return try? JSONDecoder().decode(WarpConfig.self, from: data)
    }
}

enum WarpRegistrationStorageError: LocalizedError {
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .keychain(let status):
            return "Не удалось сохранить ключи в Keychain (код \(status))."
        }
    }
}
