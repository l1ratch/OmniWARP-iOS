import Foundation
import Observation

/// Полностью автоматический сценарий настройки WARP:
/// регистрация → scout → проверка нескольких AWG-профилей → сохранение → connect.
@MainActor
@Observable
final class AutoSetupViewModel {
    var isRunning = false
    var progress: Double = 0
    var phaseMessage = "Готово к автоматической настройке"
    var statusMessage: String?
    var errorMessage: String?

    @ObservationIgnored
    private var runTask: Task<Void, Never>?

    private struct BestConfiguration {
        let validation: CandidateValidation
        let params: AmneziaWGParams
    }

    func start(
        registration: WarpRegistrationViewModel,
        tunnel: TunnelManager,
        domainLists: [DomainListEntry],
        awgSettings: AWGSettingsViewModel
    ) {
        guard runTask == nil, !isRunning else { return }
        statusMessage = nil
        errorMessage = nil
        progress = 0
        runTask = Task { [weak self] in
            guard let self else { return }
            await self.run(registration: registration, tunnel: tunnel, domainLists: domainLists, awgSettings: awgSettings)
            self.runTask = nil
        }
    }

    func cancel() {
        runTask?.cancel()
    }

    private func run(
        registration: WarpRegistrationViewModel,
        tunnel: TunnelManager,
        domainLists: [DomainListEntry],
        awgSettings: AWGSettingsViewModel
    ) async {
        isRunning = true
        defer { isRunning = false }

        do {
            phaseMessage = "Проверяем WARP-регистрацию"
            progress = 0.03
            if registration.config == nil {
                phaseMessage = "Получаем бесплатные ключи WARP"
                await registration.register(
                    amneziaWG: .zapretPreset,
                    endpoint: EndpointScout.fallbackCandidate
                )
            }
            guard var baseConfig = registration.config else {
                throw AutoSetupError.registrationFailed(
                    registration.lastError ?? "Сервер не вернул конфигурацию WARP."
                )
            }
            try Task.checkCancellation()

            phaseMessage = "Ищем быстрые точки входа Cloudflare"
            let scoutCandidates = try await EndpointScout().scout { [weak self] update in
                Task { @MainActor in
                    self?.progress = 0.05 + update.fraction * 0.20
                }
            }
            let endpoints = Array(scoutCandidates.prefix(3))
            guard !endpoints.isEmpty else { throw AutoSetupError.noEndpoints }
            try Task.checkCancellation()

            let profiles: [AmneziaWGParams] = [.zapretPreset, .random(), .random()]
            var best: BestConfiguration?
            var restorationErrors: [String] = []

            for (profileIndex, params) in profiles.enumerated() {
                try Task.checkCancellation()
                baseConfig.amneziaWG = params
                phaseMessage = "Проверяем AWG-профиль \(profileIndex + 1)/\(profiles.count): Jc=\(params.jc), \(params.jmin)–\(params.jmax)"

                let driver = AppTunnelTestDriver(tunnelManager: tunnel)
                let validator = CandidateValidator(
                    configuration: ValidationConfiguration(
                        rttPlan: RTTProbePlan(attempts: 3, timeout: 2, transport: .tcp),
                        maxAttempts: endpoints.count,
                        maxDuration: 120,
                        stopAfterFreshColos: 3
                    ),
                    driver: driver
                )
                let report = await validator.validate(
                    endpoints: endpoints,
                    baseConfiguration: baseConfig
                )
                restorationErrors.append(contentsOf: driver.restorationErrors)
                try Task.checkCancellation()

                if let candidate = report.best {
                    let candidateBest = BestConfiguration(validation: candidate, params: params)
                    if best == nil || Self.isBetter(candidate, than: best!.validation) {
                        best = candidateBest
                    }
                }
                progress = 0.25 + Double(profileIndex + 1) / Double(profiles.count) * 0.65
            }

            guard let best else {
                throw AutoSetupError.noWorkingConfiguration(
                    restorationErrors.isEmpty ? nil : restorationErrors.joined(separator: "; ")
                )
            }

            let target = best.validation.target
            let endpoint = EndpointCandidate(
                ip: target.host,
                port: target.port,
                colo: best.validation.colo,
                rttMilliseconds: best.validation.medianRTTMs ?? best.validation.rankedRTTMs,
                lossPercentage: best.validation.lossPercentage,
                httpsStatus: best.validation.https?.httpStatus,
                source: .anchor
            )
            var selectedConfig = baseConfig
            selectedConfig.amneziaWG = best.params
            selectedConfig = selectedConfig.withEndpoint(endpoint)
            _ = try selectedConfig.wgQuickData()

            try Task.checkCancellation()
            phaseMessage = "Сохраняем лучший конфиг"
            progress = 0.93
            try registration.save(selectedConfig)
            // Ручной reconnect использует тот же профиль, что и автоподбор.
            awgSettings.apply(best.params)

            let descriptors = domainLists.filter(\.isEnabled).compactMap { entry -> DomainListDescriptor? in
                guard let url = URL(string: entry.url) else { return nil }
                return DomainListDescriptor(id: entry.id, url: url, enabled: true, name: entry.title)
            }
            let snapshot = try ConfigurationSnapshot(
                awgParamsData: JSONEncoder().encode(best.params),
                warpConfigData: selectedConfig.wgQuickData(),
                domainLists: descriptors,
                splitTunnelingEnabled: !descriptors.isEmpty,
                dnsServers: selectedConfig.dns
            ).jsonData()

            try Task.checkCancellation()
            phaseMessage = "Запускаем туннель"
            progress = 0.97
            await tunnel.connect(
                snapshotJSON: snapshot,
                endpoint: endpoint.id,
                colo: best.validation.colo
            )
            if let lastError = tunnel.lastError, !lastError.isEmpty {
                throw AutoSetupError.connectionFailed(lastError)
            }

            let rtt = best.validation.rankedRTTMs.map { String(format: "%.0f мс", $0) } ?? "RTT неизвестен"
            statusMessage = "Выбран \(endpoint.id), colo \(best.validation.colo ?? "—"), \(rtt), Jc=\(best.params.jc). Конфиг сохранён, туннель запускается."
            if !restorationErrors.isEmpty {
                statusMessage? += " При восстановлении тестовых туннелей были предупреждения: \(restorationErrors.joined(separator: "; "))"
            }
            phaseMessage = "Автоматическая настройка завершена"
            progress = 1
        } catch is CancellationError {
            phaseMessage = "Автоматическая настройка отменена"
            statusMessage = "Операция отменена. Рабочий конфиг не считается выбранным."
        } catch {
            errorMessage = error.localizedDescription
            phaseMessage = "Не удалось собрать рабочий конфиг"
        }
    }

    private static func isBetter(_ lhs: CandidateValidation, than rhs: CandidateValidation) -> Bool {
        let leftBucket = lhs.bucket?.rawValue ?? Int.max
        let rightBucket = rhs.bucket?.rawValue ?? Int.max
        if leftBucket != rightBucket { return leftBucket < rightBucket }
        let leftRTT = lhs.rankedRTTMs ?? .infinity
        let rightRTT = rhs.rankedRTTMs ?? .infinity
        if leftRTT != rightRTT { return leftRTT < rightRTT }
        if lhs.lossFraction != rhs.lossFraction { return lhs.lossFraction < rhs.lossFraction }
        return lhs.target < rhs.target
    }
}

enum AutoSetupError: LocalizedError {
    case registrationFailed(String)
    case noEndpoints
    case noWorkingConfiguration(String?)
    case connectionFailed(String)

    var errorDescription: String? {
        switch self {
        case .registrationFailed(let reason):
            return "Не удалось получить WARP-конфигурацию: \(reason)"
        case .noEndpoints:
            return "EndpointScout не нашёл точки входа для проверки."
        case .noWorkingConfiguration(let restorationDetails):
            var message = "Ни один AWG-профиль не прошёл handshake + HTTPS. Подключение не выполнялось."
            if let restorationDetails, !restorationDetails.isEmpty {
                message += " Ошибки восстановления тестовых туннелей: \(restorationDetails)"
            }
            return message
        case .connectionFailed(let reason):
            return "Конфиг выбран и сохранён, но запуск туннеля не удался: \(reason)"
        }
    }
}
