import Foundation
import NetworkExtension

/// Состояние ответа core, а не только состояние системного VPN-соединения.
enum CoreHealth: Equatable {
    case unknown
    case checking
    case available
    case unavailable(String)
}

struct TunnelTrafficStats: Equatable {
    var receivedBytes: UInt64 = 0
    var transmittedBytes: UInt64 = 0
    var lastHandshake: Date?
}

enum TunnelManagerError: LocalizedError {
    case missingProvider
    case providerMessage(String)
    case malformedProviderResponse

    var errorDescription: String? {
        switch self {
        case .missingProvider:
            return "Системный VPN-провайдер недоступен. Установите и включите конфигурацию OmniWARP."
        case .providerMessage(let message):
            return message
        case .malformedProviderResponse:
            return "Ядро вернуло неподдерживаемый ответ. Подключение не считается подтверждённым."
        }
    }
}

/// Владеет NETunnelProviderManager и сериализует все операции на MainActor.
/// Каждое новое действие увеличивает generation: устаревшие watchdog и stats-запросы
/// не могут изменить состояние после отключения или повторного подключения.
@MainActor
final class TunnelManager: ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var coreHealth: CoreHealth = .unknown
    @Published private(set) var trafficStats: TunnelTrafficStats?
    @Published private(set) var isBusy = false
    @Published private(set) var lastError: String?
    @Published private(set) var currentEndpoint: String?
    @Published private(set) var currentColo: String?
    @Published private(set) var toggleGeneration: UInt64 = 0
    @Published private(set) var isTestingCandidates = false

    private let providerBundleIdentifier: String
    private var manager: NETunnelProviderManager?
    private var testSessionDepth = 0
    private var statusObservation: StatusObservation?
    private var watchdogTask: Task<Void, Never>?
    private var statsTask: Task<Void, Never>?
    private var statsRequestInFlight = false

    init(providerBundleIdentifier: String? = nil) {
        self.providerBundleIdentifier = providerBundleIdentifier
            ?? Bundle.main.bundleIdentifier.map { "\($0).tunnel" }
            ?? "com.omniwarp.OmniWARP.tunnel"
        observeStatus()
    }

    /// Освобождает observer без доступа к isolated-состоянию из nonisolated deinit.
    private final class StatusObservation {
        private let observer: NSObjectProtocol

        init(_ observer: NSObjectProtocol) {
            self.observer = observer
        }

        deinit {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    var isTunnelActive: Bool {
        status == .connected || status == .connecting || status == .reasserting
    }

    var statusTitle: String {
        if isTestingCandidates { return "Проверка endpoint’ов" }
        switch status {
        case .invalid: return "Не настроен"
        case .disconnected: return "Отключено"
        case .connecting: return "Подключение"
        case .connected: return "Системный туннель активен"
        case .reasserting: return "Восстановление"
        case .disconnecting: return "Отключение"
        @unknown default: return "Неизвестное состояние"
        }
    }

    var coreStatusTitle: String {
        switch coreHealth {
        case .unknown: return "Состояние ядра не подтверждено"
        case .checking: return "Проверяем ответ ядра"
        case .available: return "Ядро отвечает на запросы"
        case .unavailable: return "Core unavailable"
        }
    }

    var coreStatusDetail: String? {
        if case .unavailable(let message) = coreHealth { return message }
        return nil
    }

    func prepare() async {
        do {
            try await loadManager()
            if let manager {
                status = manager.connection.status
                restoreEndpointFromConfiguration(manager)
                applyConnectionStatus()
            }
        } catch {
            lastError = error.localizedDescription
        }
    }

    func beginCandidateTesting() {
        testSessionDepth += 1
        isTestingCandidates = true
        advanceGeneration()
        coreHealth = .unknown
        trafficStats = nil
        isBusy = true
    }

    func endCandidateTesting() {
        testSessionDepth = max(0, testSessionDepth - 1)
        guard testSessionDepth == 0 else { return }
        isTestingCandidates = false
        isBusy = false
        Task { await self.prepare() }
    }

    func toggle(snapshotJSON: Data, endpoint: String, colo: String?) async {
        guard !isTestingCandidates else { return }
        if isTunnelActive || status == .disconnecting {
            disconnect()
        } else {
            await connect(snapshotJSON: snapshotJSON, endpoint: endpoint, colo: colo)
        }
    }

    func connect(snapshotJSON: Data, endpoint: String, colo: String?) async {
        guard !isBusy else { return }
        guard String(decoding: snapshotJSON, as: UTF8.self).isEmpty == false else {
            lastError = "Конфигурация пуста. Проверьте настройки перед подключением."
            return
        }

        advanceGeneration()
        isBusy = true
        lastError = nil
        coreHealth = .unknown
        trafficStats = nil
        let generation = toggleGeneration

        do {
            try await loadManager()
            let tunnelManager = manager ?? NETunnelProviderManager()
            let providerProtocol = (tunnelManager.protocolConfiguration as? NETunnelProviderProtocol)
                ?? NETunnelProviderProtocol()
            providerProtocol.providerBundleIdentifier = providerBundleIdentifier
            providerProtocol.providerConfiguration = [
                ConfigurationSnapshot.providerConfigurationKey: snapshotJSON
            ]
            tunnelManager.protocolConfiguration = providerProtocol
            tunnelManager.localizedDescription = "OmniWARP"
            tunnelManager.isEnabled = true

            try await tunnelManager.saveToPreferences()
            try await tunnelManager.loadFromPreferences()
            manager = tunnelManager
            currentEndpoint = endpoint
            currentColo = colo
            observeStatus()

            try tunnelManager.connection.startVPNTunnel(options: [
                ConfigurationSnapshot.providerConfigurationKey: snapshotJSON
            ])
            status = tunnelManager.connection.status
            startWatchdog(generation: generation)
        } catch {
            guard generation == toggleGeneration else { return }
            isBusy = false
            lastError = error.localizedDescription
            coreHealth = .unavailable("Core unavailable: \(error.localizedDescription)")
        }
    }

    func disconnect() {
        advanceGeneration()
        watchdogTask?.cancel()
        statsTask?.cancel()
        isBusy = false
        coreHealth = .unknown
        trafficStats = nil
        manager?.connection.stopVPNTunnel()
        if manager == nil { status = .disconnected }
    }

    func refreshStats() async {
        guard status == .connected, statsRequestInFlight == false else { return }
        let generation = toggleGeneration
        statsRequestInFlight = true
        coreHealth = .checking
        defer { statsRequestInFlight = false }

        do {
            let data = try await sendStatsRequest()
            let decoded = try decodeStatsResponse(data)
            guard generation == toggleGeneration, status == .connected else { return }
            trafficStats = decoded
            coreHealth = .available
        } catch {
            guard generation == toggleGeneration, status == .connected else { return }
            let message = error.localizedDescription
            coreHealth = .unavailable(message)
            lastError = message.contains("Core unavailable") ? message : "Core unavailable: \(message)"
        }
    }

    private func loadManager() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        if let existing = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleIdentifier
        }) ?? managers.first {
            manager = existing
            status = existing.connection.status
        }
        observeStatus()
    }

    private func advanceGeneration() {
        toggleGeneration = toggleGeneration &+ 1
        watchdogTask?.cancel()
        statsTask?.cancel()
        statsRequestInFlight = false
    }

    private func observeStatus() {
        guard statusObservation == nil else { return }
        let observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            Task { @MainActor in
                guard let self else { return }
                if let connection = notification.object as? NEVPNConnection,
                   let managerConnection = self.manager?.connection,
                   connection !== managerConnection {
                    return
                }
                self.applyConnectionStatus()
            }
        }
        statusObservation = StatusObservation(observer)
    }

    private func applyConnectionStatus() {
        guard let manager else { return }
        status = manager.connection.status
        guard !isTestingCandidates else { return }
        switch status {
        case .connected:
            isBusy = false
            watchdogTask?.cancel()
            if coreHealth == .unknown { coreHealth = .checking }
            startStatsPolling(generation: toggleGeneration)
        case .connecting, .reasserting:
            isBusy = true
        case .disconnecting:
            isBusy = true
            statsTask?.cancel()
        case .disconnected, .invalid:
            isBusy = false
            watchdogTask?.cancel()
            statsTask?.cancel()
            coreHealth = .unknown
            trafficStats = nil
        @unknown default:
            isBusy = false
        }
    }

    private func startWatchdog(generation: UInt64) {
        watchdogTask?.cancel()
        watchdogTask = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(20)) } catch { return }
            guard let self, !Task.isCancelled else { return }
            guard self.toggleGeneration == generation else { return }
            guard self.status != .connected else { return }

            self.manager?.connection.stopVPNTunnel()
            self.status = self.manager?.connection.status ?? .disconnected
            self.isBusy = false
            self.lastError = "Ядро не перевело туннель в активное состояние за 20 секунд. Проверьте логи и параметры."
            self.coreHealth = .unavailable("Core unavailable: время ожидания запуска истекло.")
        }
    }

    private func startStatsPolling(generation: UInt64) {
        statsTask?.cancel()
        statsTask = Task { [weak self] in
            while !Task.isCancelled {
                guard self?.toggleGeneration == generation, self?.status == .connected else { return }
                await self?.refreshStats()
                do { try await Task.sleep(for: .seconds(5)) } catch { return }
            }
        }
    }

    private func sendStatsRequest() async throws -> Data {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            throw TunnelManagerError.missingProvider
        }
        return try await ProviderMessageClient.stats(from: session)
    }

    private func decodeStatsResponse(_ data: Data) throws -> TunnelTrafficStats {
        let object = try JSONSerialization.jsonObject(with: data)
        guard let root = object as? [String: Any] else {
            throw TunnelManagerError.malformedProviderResponse
        }
        if root["ok"] as? Bool == false {
            let message = root["error"] as? String ?? "Ядро сообщило об ошибке валидатора."
            throw TunnelManagerError.providerMessage(message)
        }
        if let error = root["error"] as? String, !error.isEmpty {
            throw TunnelManagerError.providerMessage(error)
        }

        let values = (root["stats"] as? [String: Any]) ?? root
        let received = Self.uint64(values, keys: ["receivedBytes", "rxBytes", "rx", "received"])
        let transmitted = Self.uint64(values, keys: ["transmittedBytes", "txBytes", "tx", "transmitted"])
        let handshake = Self.double(values, keys: ["lastHandshake", "lastHandshakeTimestamp", "handshakeAt"])
        guard received != nil || transmitted != nil || handshake != nil else {
            throw TunnelManagerError.malformedProviderResponse
        }

        return TunnelTrafficStats(
            receivedBytes: received ?? 0,
            transmittedBytes: transmitted ?? 0,
            lastHandshake: handshake.flatMap { $0 > 0 ? Date(timeIntervalSince1970: $0) : nil }
        )
    }

    private func restoreEndpointFromConfiguration(_ manager: NETunnelProviderManager) {
        guard let data = (manager.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?[ConfigurationSnapshot.providerConfigurationKey] as? Data,
              let snapshot = try? ConfigurationSnapshot(jsonData: data),
              let configuration = String(data: snapshot.warpConfigData, encoding: .utf8) else { return }

        for rawLine in configuration.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("Endpoint"), let separator = line.firstIndex(of: "=") else { continue }
            currentEndpoint = line[line.index(after: separator)...]
                .trimmingCharacters(in: .whitespaces)
            break
        }
        currentColo = nil
    }

    private static func uint64(_ values: [String: Any], keys: [String]) -> UInt64? {
        for key in keys {
            if let value = values[key] as? UInt64 { return value }
            if let value = values[key] as? NSNumber { return value.uint64Value }
            if let value = values[key] as? String { return UInt64(value) }
        }
        return nil
    }

    private static func double(_ values: [String: Any], keys: [String]) -> Double? {
        for key in keys {
            if let value = values[key] as? Double { return value }
            if let value = values[key] as? NSNumber { return value.doubleValue }
            if let value = values[key] as? String { return Double(value) }
        }
        return nil
    }
}
