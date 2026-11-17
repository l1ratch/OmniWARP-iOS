import SwiftUI

enum AppConfigurationError: LocalizedError {
    case missingAWG
    case missingEndpoint
    case missingWarpConfig

    var errorDescription: String? {
        switch self {
        case .missingAWG:
            return "Параметры AWG не прошли проверку. Исправьте их на вкладке AWG."
        case .missingEndpoint:
            return "Не выбран endpoint. Выполните подбор или укажите endpoint конфигурации."
        case .missingWarpConfig:
            return "Нет ключей WARP. Нажмите «Получить ключи» на вкладке «Статус»."
        }
    }
}

@MainActor
struct RootView: View {
    @StateObject private var tunnelManager = TunnelManager()
    @State private var scouting = ScoutingViewModel()
    @State private var domainLists = DomainListsViewModel()
    @State private var awg = AWGSettingsViewModel()
    @State private var registration = WarpRegistrationViewModel()
    @State private var autoSetup = AutoSetupViewModel()

    var body: some View {
        TabView {
            StatusView(
                tunnel: tunnelManager,
                registration: registration,
                autoSetup: autoSetup,
                configuredEndpoint: selectedEndpoint,
                configuredColo: selectedColo,
                isScouting: scouting.isRunning,
                makeSnapshot: makeSnapshot,
                registerWarp: registerWarp,
                startAutoSetup: startAutomaticSetup
            )
            .tabItem {
                Label("Статус", systemImage: "power")
            }

            ScoutingView(model: scouting)
                .tabItem {
                    Label("Подбор", systemImage: "scope")
                }

            DomainListsView(model: domainLists)
                .tabItem {
                    Label("Домены", systemImage: "list.bullet")
                }

            AWGSettingsView(model: awg)
                .tabItem {
                    Label("AWG", systemImage: "slider.horizontal.3")
                }
        }
        .onAppear(perform: configureScouting)
        .task {
            await tunnelManager.prepare()
        }
    }

    private var selectedEndpointCandidate: EndpointCandidate {
        scouting.selectedCandidate?.endpointCandidate
            ?? registration.config?.endpoint
            ?? EndpointScout.fallbackCandidate
    }

    private var selectedEndpoint: String {
        selectedEndpointCandidate.id
    }

    private var selectedColo: String? {
        selectedEndpointCandidate.colo
    }

    private func configureScouting() {
        scouting.scoutingOperation = { progress in
            let result = try await EndpointScout().scout { update in
                progress(update.fraction)
            }
            return result.map(ScoutingCandidate.init)
        }
        scouting.validationOperation = { candidates, progress in
            try await validateCandidates(candidates, progress: progress)
        }
    }

    private func validateCandidates(
        _ candidates: [ScoutingCandidate],
        progress: @escaping (Double) -> Void
    ) async throws -> ScoutingValidationResult {
        guard registration.config != nil else {
            return ScoutingValidationResult(
                candidates: candidates,
                preferredCandidateID: nil,
                warning: "Для полной проверки handshake получите ключи WARP. Показаны только HTTP-метрики scout.",
                summary: nil
            )
        }

        let params = try awg.validatedValues()
        let baseConfiguration = try registration.configuration(
            amneziaWG: params,
            endpoint: selectedEndpointCandidate
        )
        let topCandidates = Array(candidates.prefix(8))
        guard topCandidates.isEmpty == false else {
            return ScoutingValidationResult(
                candidates: candidates,
                preferredCandidateID: nil,
                warning: "EndpointScout не вернул кандидатов для полной проверки.",
                summary: nil
            )
        }

        let validationProgress = ValidationProgress()
        let stream = validationProgress.makeStream()
        let consumer = Task { @MainActor in
            for await event in stream {
                if case .candidateFinished(let validation) = event {
                    progress(Double(validation.index) / Double(topCandidates.count))
                }
            }
        }
        let configuration = ValidationConfiguration(
            rttPlan: RTTProbePlan(attempts: 3, timeout: 2, transport: .tcp),
            maxAttempts: 8
        )
        let driver = AppTunnelTestDriver(tunnelManager: tunnelManager)
        let validator = CandidateValidator(
            configuration: configuration,
            driver: driver,
            progress: validationProgress
        )
        let report = await validator.validate(
            endpoints: topCandidates.map(\.endpointCandidate),
            baseConfiguration: baseConfiguration
        )
        await consumer.value
        progress(1)

        let restorationWarning = driver.restorationErrors.isEmpty ? nil :
            "Не удалось полностью восстановить production-туннель: \(driver.restorationErrors.joined(separator: "; ")). Проверьте состояние на вкладке «Статус»."

        if case .driverUnavailable(let reason) = report.stopReason {
            let unavailableWarning = "CandidateValidator недоступен: \(reason). Показаны только HTTP-метрики scout."
            return ScoutingValidationResult(
                candidates: candidates,
                preferredCandidateID: nil,
                warning: [unavailableWarning, restorationWarning].compactMap { $0 }.joined(separator: " "),
                summary: nil
            )
        }

        var merged = candidates
        for validation in report.validations {
            guard let index = merged.firstIndex(where: { $0.id == validation.displayEndpoint }) else { continue }
            merged[index].apply(validation)
        }
        let summary = "Полная проверка: подтверждено \(report.ranked.count) из \(report.attemptedCount). \(report.stopReason.message)"
        let validationWarning = report.isActionable ? nil : "Ни один кандидат не получил полное подтверждение handshake + HTTPS."
        let warnings = [validationWarning, restorationWarning].compactMap { $0 }
        return ScoutingValidationResult(
            candidates: merged,
            preferredCandidateID: report.best?.displayEndpoint,
            warning: warnings.isEmpty ? nil : warnings.joined(separator: " "),
            summary: summary
        )
    }

    private func startAutomaticSetup() {
        autoSetup.start(
            registration: registration,
            tunnel: tunnelManager,
            domainLists: domainLists.enabledLists,
            awgSettings: awg
        )
    }

    private func registerWarp() async {
        do {
            let params = try awg.validatedValues()
            await registration.register(
                amneziaWG: params,
                endpoint: selectedEndpointCandidate
            )
        } catch {
            registration.report(error: error)
        }
    }

    /// Снимок содержит настоящий wg-quick текст и актуальные AWG-параметры.
    /// Без зарегистрированного WarpConfig подключение честно блокируется.
    private func makeSnapshot() throws -> Data {
        let values = try awg.validatedValues()
        guard selectedEndpoint.isEmpty == false else { throw AppConfigurationError.missingEndpoint }

        let config = try registration.configuration(
            amneziaWG: values,
            endpoint: selectedEndpointCandidate
        )
        let warpConfigData = try config.wgQuickData()
        guard warpConfigData.isEmpty == false else { throw AppConfigurationError.missingWarpConfig }

        let descriptors = domainLists.enabledLists.compactMap { entry -> DomainListDescriptor? in
            guard let url = URL(string: entry.url) else { return nil }
            return DomainListDescriptor(id: entry.id, url: url, enabled: true, name: entry.title)
        }
        return try ConfigurationSnapshot(
            awgParamsData: JSONEncoder().encode(values),
            warpConfigData: warpConfigData,
            domainLists: descriptors,
            splitTunnelingEnabled: descriptors.isEmpty == false,
            dnsServers: config.dns
        ).jsonData()
    }
}
