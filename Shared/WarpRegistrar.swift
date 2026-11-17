import CryptoKit
import Foundation
import Network

/// Регистрация WARP без внешних процессов и без NetworkExtension.
/// Приватный ключ создаётся CryptoKit, возвращается только в WarpConfig и никогда не логируется.
public struct WarpRegistrar: Sendable {
    public enum Endpoint: Sendable {
        case primary
        case fallback

        var url: URL {
            switch self {
            case .primary: return URL(string: "https://wgcli.vercel.app/api/reg")!
            case .fallback: return URL(string: "https://santa-atmo.ru/warp/warp.php")!
            }
        }
    }

    private let session: URLSession
    private let requestTimeout: TimeInterval

    public init(requestTimeout: TimeInterval = 15, session: URLSession? = nil) {
        self.requestTimeout = max(1, requestTimeout)
        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = self.requestTimeout
            configuration.timeoutIntervalForResource = self.requestTimeout * 2
            configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            configuration.urlCache = nil
            configuration.httpCookieStorage = nil
            configuration.httpShouldSetCookies = false
            self.session = URLSession(configuration: configuration)
        }
    }

    /// Пробует primary, затем fallback. Ошибки HTTP/JSON не содержат тело ответа,
    /// чтобы ключи и данные регистрации случайно не попали в логи.
    public func register(
        amneziaWG: AmneziaWGParams = .zapretManager,
        endpoint: EndpointCandidate? = nil,
        installID: String = "",
        fcmToken: String = "",
        model: String = "PC",
        locale: String = "en_US"
    ) async throws -> WarpConfig {
        try Task.checkCancellation()
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey.rawRepresentation.base64EncodedString()
        let requestBody = RegistrationRequest(
            key: publicKey,
            installID: installID,
            fcmToken: fcmToken,
            model: model,
            locale: locale,
            tos: ISO8601DateFormatter().string(from: Date()),
            type: "Android"
        )

        for registrationEndpoint in [Endpoint.primary, .fallback] {
            do {
                let remote = try await performRegistration(
                    to: registrationEndpoint,
                    body: requestBody
                )
                // Основной сервер регистрирует наш публичный ключ. Резервный
                // GET endpoint возвращает готовую регистрацию и СВОЙ приватный
                // ключ в result.key — подменять его локальным ключом нельзя.
                let configPrivateKey: String
                switch registrationEndpoint {
                case .primary:
                    configPrivateKey = privateKey.rawRepresentation.base64EncodedString()
                case .fallback:
                    guard let returnedKey = remote.privateKey else {
                        throw WarpRegistrarError.invalidPrivateKey
                    }
                    configPrivateKey = returnedKey
                }
                return WarpConfig(
                    privateKey: configPrivateKey,
                    peerPublicKey: remote.peerPublicKey,
                    addresses: remote.addresses,
                    endpoint: endpoint,
                    amneziaWG: amneziaWG
                )
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try Task.checkCancellation()
                if (error as? URLError)?.code == .cancelled { throw CancellationError() }
                // Переходим к fallback; текст сетевого ответа здесь намеренно не сохраняется.
            }
        }
        throw WarpRegistrarError.allRegistrarsFailed
    }

    private func performRegistration(
        to endpoint: Endpoint,
        body: RegistrationRequest
    ) async throws -> RemoteConfiguration {
        var request = URLRequest(
            url: endpoint.url,
            cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
            timeoutInterval: requestTimeout
        )
        // Zapret-Manager использует разные методы: основной api/reg — POST,
        // резервный warp.php — GET (он возвращает готовую регистрацию).
        switch endpoint {
        case .primary:
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONEncoder().encode(body)
        case .fallback:
            request.httpMethod = "GET"
            request.httpBody = nil
        }
        request.httpShouldHandleCookies = false
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("okhttp/3.12.1", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw WarpRegistrarError.invalidResponse
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            throw WarpRegistrarError.httpStatus(httpResponse.statusCode)
        }
        guard !data.isEmpty, data.count <= 4_194_304 else {
            throw WarpRegistrarError.invalidResponse
        }
        return try Self.decodeRemoteConfiguration(data)
    }

    private static func decodeRemoteConfiguration(_ data: Data) throws -> RemoteConfiguration {
        let envelope: RegistrationEnvelope
        do {
            envelope = try JSONDecoder().decode(RegistrationEnvelope.self, from: data)
        } catch {
            throw WarpRegistrarError.invalidResponse
        }

        var containers: [RegistrationConfigValues] = [envelope]
        if let result = envelope.result {
            containers.append(result)
            if let config = result.config { containers.append(config) }
        }
        if let config = envelope.config { containers.append(config) }

        guard let peerKey = containers.lazy.compactMap({ $0.peers?.first?.publicKey }).first,
              let keyData = Data(base64Encoded: peerKey), keyData.count == 32,
              (try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyData)) != nil else {
            throw WarpRegistrarError.invalidPeerKey
        }

        let addresses = containers.lazy.compactMap { container -> RegistrationAddresses? in
            container.interface?.addresses ?? container.addresses
        }.first

        let ipv4 = try normalizeAddress(addresses?.v4, version: .ipv4)
        let ipv6 = try normalizeAddress(addresses?.v6, version: .ipv6)
        let normalized = [ipv4, ipv6].compactMap { $0 }
        guard !normalized.isEmpty else { throw WarpRegistrarError.missingAddresses }

        let returnedPrivateKey = envelope.result?.key ?? envelope.key
        if let returnedPrivateKey {
            guard let keyData = Data(base64Encoded: returnedPrivateKey), keyData.count == 32 else {
                throw WarpRegistrarError.invalidPrivateKey
            }
        }
        return RemoteConfiguration(
            peerPublicKey: peerKey,
            addresses: normalized,
            privateKey: returnedPrivateKey
        )
    }

    private static func normalizeAddress(_ raw: String?, version: IPVersion) throws -> String? {
        guard let raw else { return nil }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return nil }
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else {
            throw WarpRegistrarError.invalidAddress
        }
        let address = String(parts[0])
        let maximumPrefix: UInt8
        switch version {
        case .ipv4:
            guard IPv4Address(address) != nil else { throw WarpRegistrarError.invalidAddress }
            maximumPrefix = 32
        case .ipv6:
            guard IPv6Address(address) != nil else { throw WarpRegistrarError.invalidAddress }
            maximumPrefix = 128
        }
        if parts.count == 2 {
            guard let prefix = UInt8(parts[1]), prefix <= maximumPrefix else {
                throw WarpRegistrarError.invalidAddress
            }
            return "\(address)/\(prefix)"
        }
        // API может вернуть как plain IP, так и уже готовый CIDR.
        return "\(address)/\(maximumPrefix)"
    }

    private struct RegistrationRequest: Encodable {
        var key: String
        var installID: String
        var fcmToken: String
        var model: String
        var locale: String
        var tos: String
        var type: String

        enum CodingKeys: String, CodingKey {
            case key
            case installID = "install_id"
            case fcmToken = "fcm_token"
            case model, locale, tos, type
        }
    }

    private struct RemoteConfiguration {
        var peerPublicKey: String
        var addresses: [String]
        var privateKey: String?
    }

    private enum IPVersion { case ipv4, ipv6 }
}

private protocol RegistrationConfigValues {
    var peers: [RegistrationPeer]? { get }
    var interface: RegistrationInterface? { get }
    var addresses: RegistrationAddresses? { get }
}

private struct RegistrationEnvelope: Decodable, RegistrationConfigValues {
    var result: RegistrationResult?
    var config: RegistrationConfig?
    var peers: [RegistrationPeer]?
    var interface: RegistrationInterface?
    var addresses: RegistrationAddresses?
    var key: String?
}

private struct RegistrationResult: Decodable, RegistrationConfigValues {
    var config: RegistrationConfig?
    var peers: [RegistrationPeer]?
    var interface: RegistrationInterface?
    var addresses: RegistrationAddresses?
    var key: String?
}

private struct RegistrationConfig: Decodable, RegistrationConfigValues {
    var peers: [RegistrationPeer]?
    var interface: RegistrationInterface?
    var addresses: RegistrationAddresses?
}

private struct RegistrationPeer: Decodable {
    var publicKey: String?

    enum CodingKeys: String, CodingKey { case publicKey = "public_key" }
}

private struct RegistrationInterface: Decodable {
    var addresses: RegistrationAddresses?
}

private struct RegistrationAddresses: Decodable {
    var v4: String?
    var v6: String?
}

public enum WarpRegistrarError: LocalizedError, Sendable {
    case httpStatus(Int)
    case invalidResponse
    case invalidPeerKey
    case invalidPrivateKey
    case missingAddresses
    case invalidAddress
    case allRegistrarsFailed

    public var errorDescription: String? {
        switch self {
        case .httpStatus(let status):
            return "Сервер регистрации WARP вернул HTTP \(status)."
        case .invalidResponse:
            return "Сервер регистрации WARP вернул некорректный JSON."
        case .invalidPeerKey:
            return "В ответе WARP отсутствует корректный peers[0].public_key."
        case .invalidPrivateKey:
            return "Резервный сервер WARP не вернул корректный приватный ключ result.key."
        case .missingAddresses:
            return "В ответе WARP отсутствуют адреса v4/v6."
        case .invalidAddress:
            return "Сервер WARP вернул некорректный адрес интерфейса."
        case .allRegistrarsFailed:
            return "Оба сервера регистрации WARP недоступны или вернули ошибку."
        }
    }
}
