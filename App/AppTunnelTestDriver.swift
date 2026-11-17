import Foundation
import NetworkExtension

/// App-side последовательный драйвер полного теста кандидата.
/// URLSession приложения идёт через default-route тестовый туннель, поэтому
/// RTT/HTTPS измеряются только после свежего handshake от provider stats.
@MainActor
final class AppTunnelTestDriver: TunnelTestDriving {
    nonisolated var availability: TunnelTestDriverAvailability {
        .available(TunnelTestCapabilities(
            backendIdentifier: Self.backendIdentifier,
            inTunnelRTT: true,
            inTunnelHTTPS: true,
            requiresExclusiveTunnel: true
        ))
    }

    private nonisolated static let backendIdentifier = "iOS NetworkExtension + WireGuardKit"

    private let providerBundleIdentifier: String
    private weak var tunnelManager: TunnelManager?
    private var activeSession: AppTunnelTestSession?
    private(set) var restorationErrors: [String] = []

    init(tunnelManager: TunnelManager? = nil, providerBundleIdentifier: String? = nil) {
        self.tunnelManager = tunnelManager
        self.providerBundleIdentifier = providerBundleIdentifier
            ?? Bundle.main.bundleIdentifier.map { "\($0).tunnel" }
            ?? "com.omniwarp.OmniWARP.tunnel"
    }

    func startTestSession(_ request: TestTunnelRequest) async throws -> any TunnelTestSession {
        guard activeSession == nil else {
            throw WarpEngineError.invalidState("Другой кандидат уже проверяется. Тесты выполняются последовательно.")
        }
        try Task.checkCancellation()

        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let manager = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleIdentifier
        }) ?? managers.first ?? NETunnelProviderManager()
        let providerProtocol = (manager.protocolConfiguration as? NETunnelProviderProtocol)
            ?? NETunnelProviderProtocol()
        let productionSnapshot = providerProtocol.providerConfiguration?[
            ConfigurationSnapshot.providerConfigurationKey
        ] as? Data
        let productionWasActive = manager.connection.status == .connected
            || manager.connection.status == .connecting
            || manager.connection.status == .reasserting
        let productionWasEnabled = manager.isEnabled

        tunnelManager?.beginCandidateTesting()
        let configuration = request.resolvedConfiguration
        let startedAt = Date()
        let session = AppTunnelTestSession(
            driver: self,
            manager: manager,
            target: request.target,
            startedAt: startedAt,
            productionSnapshot: productionSnapshot,
            productionWasActive: productionWasActive,
            productionWasEnabled: productionWasEnabled,
            tunnelManager: tunnelManager
        )
        activeSession = session

        do {
            if productionWasActive || manager.connection.status == .disconnecting {
                manager.connection.stopVPNTunnel()
                await Self.waitForDisconnected(manager.connection, timeout: 5)
            }

            let snapshot = try ConfigurationSnapshot(
                awgParamsData: JSONEncoder().encode(configuration.amneziaWG),
                warpConfigData: configuration.wgQuickData(),
                domainLists: [],
                splitTunnelingEnabled: false,
                dnsServers: configuration.dns
            ).jsonData()
            providerProtocol.providerBundleIdentifier = providerBundleIdentifier
            providerProtocol.providerConfiguration = [ConfigurationSnapshot.providerConfigurationKey: snapshot]
            manager.protocolConfiguration = providerProtocol
            manager.localizedDescription = "OmniWARP — проверка endpoint"
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            try manager.connection.startVPNTunnel(options: [
                ConfigurationSnapshot.providerConfigurationKey: snapshot
            ])
            return session
        } catch {
            await session.stop()
            throw error
        }
    }

    fileprivate func sessionDidStop(_ session: AppTunnelTestSession) {
        if activeSession === session { activeSession = nil }
    }

    fileprivate func reportRestorationError(_ error: Error) {
        restorationErrors.append(error.localizedDescription)
    }

    fileprivate static func waitForDisconnected(_ connection: NEVPNConnection, timeout: TimeInterval) async {
        let deadline = WarpMonotonicClock.now() + timeout
        while WarpMonotonicClock.now() < deadline {
            if connection.status == .disconnected || connection.status == .invalid { return }
            do { try await Task.sleep(for: .milliseconds(100)) } catch { return }
        }
    }
}

@MainActor
final class AppTunnelTestSession: TunnelTestSession {
    nonisolated let target: CandidateTarget
    nonisolated let backend = WarpEngineBackend(
        identifier: "iOS NetworkExtension + WireGuardKit",
        inTunnelRTT: true,
        inTunnelHTTPS: true
    )

    private weak var driver: AppTunnelTestDriver?
    private let manager: NETunnelProviderManager
    private let startedAt: Date
    private let productionSnapshot: Data?
    private let productionWasActive: Bool
    private let productionWasEnabled: Bool
    private weak var tunnelManager: TunnelManager?
    private var handshakeOutcome: HandshakeOutcome?
    private var stopped = false

    init(
        driver: AppTunnelTestDriver,
        manager: NETunnelProviderManager,
        target: CandidateTarget,
        startedAt: Date,
        productionSnapshot: Data?,
        productionWasActive: Bool,
        productionWasEnabled: Bool,
        tunnelManager: TunnelManager?
    ) {
        self.driver = driver
        self.manager = manager
        self.target = target
        self.startedAt = startedAt
        self.productionSnapshot = productionSnapshot
        self.productionWasActive = productionWasActive
        self.productionWasEnabled = productionWasEnabled
        self.tunnelManager = tunnelManager
    }

    func waitForHandshake(timeout: TimeInterval) async throws -> HandshakeOutcome {
        guard !stopped else { throw WarpEngineError.invalidState("Тестовая сессия уже остановлена.") }
        let clockStart = WarpMonotonicClock.now()
        let deadline = clockStart + max(0.5, timeout)

        while WarpMonotonicClock.now() < deadline {
            if Task.isCancelled { throw WarpEngineError.cancelled }
            if manager.connection.status == .connected {
                do {
                    let stats = try await requestStats()
                    if let handshakeAt = stats.lastHandshakeAt,
                       handshakeAt >= startedAt.addingTimeInterval(-1) {
                        let outcome = HandshakeOutcome(
                            observedAt: Date(),
                            lastHandshakeAt: handshakeAt,
                            attemptDurationMs: WarpMonotonicClock.millisecondsSince(clockStart),
                            source: .runtimeConfiguration,
                            rxBytes: stats.receivedBytes ?? 0,
                            txBytes: stats.transmittedBytes ?? 0
                        )
                        handshakeOutcome = outcome
                        return outcome
                    }
                } catch {
                    // Core может ещё запускаться. Повторяем до deadline;
                    // сам факт NE connected handshake не подтверждает.
                }
            } else if manager.connection.status == .disconnected || manager.connection.status == .invalid {
                throw WarpEngineError.handshakeFailed("Системный тестовый туннель отключился до handshake.")
            }
            do { try await Task.sleep(for: .milliseconds(250)) } catch { throw WarpEngineError.cancelled }
        }
        throw WarpEngineError.handshakeTimeout
    }

    func probeRTT(_ plan: RTTProbePlan) async -> RTTProbeOutcome {
        guard hasUsableTestTunnel else {
            return .unsupported("RTT измеряется только при активном тестовом туннеле и подтверждённом handshake.")
        }
        var samples: [RTTProbeSample] = []
        for round in 1...plan.attempts {
            if Task.isCancelled { return .cancelled }
            guard var components = URLComponents(string: "http://www.cloudflare.com/cdn-cgi/trace") else {
                return .unsupported("Не удалось сформировать URL RTT-пробы.")
            }
            components.queryItems = [URLQueryItem(name: "rtt", value: UUID().uuidString)]
            guard let probeURL = components.url else { continue }

            var request = URLRequest(
                url: probeURL,
                cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
                timeoutInterval: plan.timeout
            )
            request.httpMethod = "GET"
            request.httpShouldHandleCookies = false
            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = plan.timeout
            configuration.timeoutIntervalForResource = plan.timeout + 0.5
            configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            configuration.urlCache = nil
            configuration.httpCookieStorage = nil
            configuration.httpShouldSetCookies = false
            let session = URLSession(configuration: configuration)
            let clock = WarpMonotonicClock.now()
            do {
                let (_, response) = try await session.data(for: request)
                let duration = WarpMonotonicClock.millisecondsSince(clock)
                if let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) {
                    samples.append(RTTProbeSample(round: round, rttMs: duration, transport: .tcp))
                }
            } catch is CancellationError {
                session.invalidateAndCancel()
                return .cancelled
            } catch {
                // Ошибка/таймаут — потерянная конкретная попытка, а не выдуманный RTT.
            }
            session.finishTasksAndInvalidate()
        }
        return .measured(RTTProbeReport(
            transport: .tcp,
            attempted: plan.attempts,
            samples: samples,
            lost: plan.attempts - samples.count
        ))
    }

    func probeHTTPS(_ plan: HTTPSProbePlan) async -> HTTPSProbeOutcome {
        guard hasUsableTestTunnel else {
            return .unsupported("HTTPS через туннель доступен только после свежего handshake.")
        }
        var request = URLRequest(
            url: plan.url,
            cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
            timeoutInterval: plan.timeout
        )
        request.httpMethod = "GET"
        request.httpShouldHandleCookies = false
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = plan.timeout
        configuration.timeoutIntervalForResource = plan.timeout + 1
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        let session = URLSession(configuration: configuration)
        let clock = WarpMonotonicClock.now()

        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                session.invalidateAndCancel()
                return .failed("Ответ не является HTTP.")
            }
            let body = String(data: data, encoding: .utf8) ?? ""
            let trace = WarpTrace(body: body)
            if plan.requireTrace && trace == nil {
                session.invalidateAndCancel()
                return .failed("HTTP-ответ не содержит распознанный cdn-cgi/trace.")
            }
            let probe = WarpHTTPSProbe(
                url: plan.url,
                httpStatus: http.statusCode,
                durationMs: WarpMonotonicClock.millisecondsSince(clock),
                bodyBytes: data.count,
                trace: trace,
                viaTunnel: hasUsableTestTunnel
            )
            session.finishTasksAndInvalidate()
            return .completed(probe)
        } catch let error as URLError {
            session.invalidateAndCancel()
            switch error.code {
            case .timedOut: return .timedOut
            case .cancelled: return .cancelled
            default: return .failed(error.localizedDescription)
            }
        } catch is CancellationError {
            session.invalidateAndCancel()
            return .cancelled
        } catch {
            session.invalidateAndCancel()
            return .failed(error.localizedDescription)
        }
    }

    func snapshotStats() async -> WarpEngineStats? {
        guard !stopped, manager.connection.status == .connected else { return nil }
        guard let stats = try? await requestStats() else { return nil }
        return WarpEngineStats(
            sampledAt: Date(),
            rxBytes: stats.receivedBytes ?? 0,
            txBytes: stats.transmittedBytes ?? 0,
            lastHandshakeAt: stats.lastHandshakeAt,
            endpoint: target.endpointString
        )
    }

    func stop() async {
        guard !stopped else { return }
        stopped = true
        handshakeOutcome = nil
        manager.connection.stopVPNTunnel()
        await AppTunnelTestDriver.waitForDisconnected(manager.connection, timeout: 5)

        if let productionSnapshot {
            let providerProtocol = (manager.protocolConfiguration as? NETunnelProviderProtocol)
                ?? NETunnelProviderProtocol()
            providerProtocol.providerConfiguration = [
                ConfigurationSnapshot.providerConfigurationKey: productionSnapshot
            ]
            manager.protocolConfiguration = providerProtocol
            manager.localizedDescription = "OmniWARP"
            manager.isEnabled = productionWasEnabled
            do {
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
                if productionWasActive {
                    try manager.connection.startVPNTunnel(options: [
                        ConfigurationSnapshot.providerConfigurationKey: productionSnapshot
                    ])
                }
            } catch {
                driver?.reportRestorationError(error)
            }
        } else {
            manager.connection.stopVPNTunnel()
        }

        driver?.sessionDidStop(self)
        tunnelManager?.endCandidateTesting()
    }

    private var hasUsableTestTunnel: Bool {
        !stopped && handshakeOutcome != nil && manager.connection.status == .connected
    }

    private func requestStats() async throws -> ProviderStats {
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw WarpEngineError.engineUnavailable("NETunnelProviderSession недоступна.")
        }
        let data = try await ProviderMessageClient.stats(from: session, timeout: 1)
        let stats = try JSONDecoder().decode(ProviderStats.self, from: data)
        if stats.ok == false {
            throw WarpEngineError.handshakeFailed(stats.error ?? "Core unavailable: ошибка валидатора.")
        }
        if let error = stats.error, !error.isEmpty {
            throw WarpEngineError.handshakeFailed(error)
        }
        return stats
    }
}

private struct ProviderStats: Decodable {
    var ok: Bool?
    var receivedBytes: UInt64?
    var transmittedBytes: UInt64?
    var lastHandshake: TimeInterval?
    var error: String?

    var lastHandshakeAt: Date? {
        lastHandshake.flatMap { $0 > 0 ? Date(timeIntervalSince1970: $0) : nil }
    }
}
