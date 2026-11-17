//
//  CandidateValidator.swift
//  OmniWARP — Tunnel
//
//  Полный валидатор кандидатов (endpoint), воспроизводящий логику панели
//  Zapret-Manager, но без выдуманных результатов.
//
//  Что и зачем
//  -----------
//  Внешний scout (`Shared/EndpointScout.swift`) быстро и дёшево отбраковывает
//  мусор UDP-пробами и отдаёт top-N кандидатов. Здесь — тяжёлая проверка:
//  для каждого кандидата поднимается временный тестовый туннель (через
//  `TunnelTestDriving`, который на iOS реализуется последовательно), ждётся
//  реальный handshake до 8 секунд, выполняются 3 RTT-пробы через туннель
//  (UDP/TCP, потому что raw ICMP недоступен), затем HTTPS-запрос
//  `https://www.cloudflare.com/cdn-cgi/trace` через туннель для получения colo.
//
//  Почему последовательно
//  ----------------------
//  iOS не позволяет двух одновременных `NEPacketTunnelProvider`. Поэтому
//  валидатор никогда не запускает проверки параллельно: один кандидат —
//  один тестовый туннель — один `stop()`. Драйвер обязан восстановить продовый
//  конфиг (см. `TestTunnelRequest.restoreProductionTunnel`).
//
//  Анти-fake-success
//  -----------------
//  * Handshake подтверждается только по данным ядра (`last_handshake_time_sec`
//    в UAPI-выгрузке), а не по «ядро запустилось».
//  * RTT — только реально измеренные пробы; если все 3 потеряны, кандидат
//    отвергается, а не получает «средний RTT».
//  * HTTPS-ответ, снятый вне туннеля (`viaTunnel == false`), доказательством
//    не считается никогда.
//  * Если драйвер не умеет HTTPS-пробу в этом контексте (например, extension
//    без netstack), кандидат получает статус `.unverified`, а не bucket.
//  * Если движок не подключён вовсе — отчёт получает `.unavailable(reason)`,
//    и ни один кандидат не объявляется живым.
//
//  Корзины (1 — лучшая)
//  --------------------
//  1. Новая colo + HTTPS: colo впервые встретилась в этом прогоне, HTTPS ok.
//  2. Та же colo, другой адрес: colo уже встречалась, но это другой endpoint.
//  3. colo unknown: HTTPS ok, но colo не определена (trace без colo).
//  4. RU colo: рабочая colo из RU-списка (штраф в ранжировании).
//  5. HTTPS fail: handshake ok, но HTTPS/путь данных не работают.
//
//  Остановка: после `stopAfterFreshColos` (по умолчанию 3) новых colo,
//  либо по лимиту попыток/дедлайну/отмене.
//

import Foundation

// MARK: - Конфигурация

/// Настройки прогона. Значения по умолчанию соответствуют ТЗ.
public struct ValidationConfiguration: Sendable, Equatable {
    /// Ожидание реального handshake, сек. По ТЗ — 8.
    public var handshakeTimeout: TimeInterval
    /// План RTT-проб: 3 попытки через туннель (UDP по умолчанию).
    public var rttPlan: RTTProbePlan
    /// План HTTPS-пробы (cdn-cgi/trace).
    public var httpsPlan: HTTPSProbePlan
    /// Верхняя граница числа поднимаемых тестовых туннелей за прогон.
    public var maxAttempts: Int
    /// Верхняя граница длительности прогона (страховка от зависаний).
    public var maxDuration: TimeInterval
    /// Сколько новых colo достаточно, чтобы прекратить перебор.
    public var stopAfterFreshColos: Int
    /// Считать ли RU colo «новой colo» для правила остановки.
    /// По умолчанию нет: пользователю нужны рабочие не-RU точки.
    public var countRUColosAsFresh: Bool
    /// Список RU colo (по данным панели Zapret-Manager).
    public var ruColos: Set<String>
    /// Штраф к RTT для RU colo при ранжировании (мс).
    public var ruColoPenaltyMs: Double
    /// Пауза между кандидатами: даёт системе «отлипнуть» от прошлого туннеля.
    public var pauseBetweenCandidates: TimeInterval
    /// Восстанавливать продовый конфиг после каждого кандидата.
    public var restoreProductionTunnel: Bool

    public static let defaultRUColos: Set<String> = [
        "DME", "SVX", "LED", "KJA", "REN", "OVB", "KZN", "AER", "VVO"
    ]

    public init(handshakeTimeout: TimeInterval = 8.0,
                rttPlan: RTTProbePlan = RTTProbePlan(attempts: 3, timeout: 2.0, transport: .udp),
                httpsPlan: HTTPSProbePlan = HTTPSProbePlan(),
                maxAttempts: Int = 8,
                maxDuration: TimeInterval = 300.0,
                stopAfterFreshColos: Int = 3,
                countRUColosAsFresh: Bool = false,
                ruColos: Set<String> = ValidationConfiguration.defaultRUColos,
                ruColoPenaltyMs: Double = 75.0,
                pauseBetweenCandidates: TimeInterval = 1.0,
                restoreProductionTunnel: Bool = true) {
        self.handshakeTimeout = max(1.0, handshakeTimeout)
        self.rttPlan = rttPlan
        self.httpsPlan = httpsPlan
        self.maxAttempts = max(1, maxAttempts)
        self.maxDuration = max(10.0, maxDuration)
        self.stopAfterFreshColos = max(1, stopAfterFreshColos)
        self.countRUColosAsFresh = countRUColosAsFresh
        self.ruColos = Set(ruColos.map { $0.uppercased() })
        self.ruColoPenaltyMs = max(0, ruColoPenaltyMs)
        self.pauseBetweenCandidates = max(0, pauseBetweenCandidates)
        self.restoreProductionTunnel = restoreProductionTunnel
    }

    /// Удобный конструктор «как в панели»: 8 с, 3 RTT, 3 colo.
    public static let panelDefaults = ValidationConfiguration()

    public var planSummary: ValidationPlanSummary {
        ValidationPlanSummary(handshakeTimeout: handshakeTimeout,
                              rttAttempts: rttPlan.attempts,
                              rttTransport: rttPlan.transport,
                              httpsURL: httpsPlan.url,
                              stopAfterFreshColos: stopAfterFreshColos,
                              maxAttempts: maxAttempts,
                              maxDuration: maxDuration)
    }
}

/// Краткое описание плана прогона — для отображения прогресса.
public struct ValidationPlanSummary: Sendable, Equatable {
    public let handshakeTimeout: TimeInterval
    public let rttAttempts: Int
    public let rttTransport: RTTProbeTransport
    public let httpsURL: URL
    public let stopAfterFreshColos: Int
    public let maxAttempts: Int
    public let maxDuration: TimeInterval

    public init(handshakeTimeout: TimeInterval,
                rttAttempts: Int,
                rttTransport: RTTProbeTransport,
                httpsURL: URL,
                stopAfterFreshColos: Int,
                maxAttempts: Int,
                maxDuration: TimeInterval) {
        self.handshakeTimeout = handshakeTimeout
        self.rttAttempts = rttAttempts
        self.rttTransport = rttTransport
        self.httpsURL = httpsURL
        self.stopAfterFreshColos = stopAfterFreshColos
        self.maxAttempts = maxAttempts
        self.maxDuration = maxDuration
    }
}

// MARK: - Корзины и статусы

/// Корзина кандидата. `rawValue` — приоритет (меньше = лучше).
public enum CandidateBucket: Int, Sendable, Equatable, CaseIterable, Comparable {
    case freshColo = 1
    case sameColoNewAddress = 2
    case unknownColo = 3
    case ruColo = 4
    case httpsFailed = 5

    public static func < (lhs: CandidateBucket, rhs: CandidateBucket) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    /// Корзина, в которой кандидат доказанно работает (с оговорками 3/4).
    public var isConfirmed: Bool { self != .httpsFailed }

    /// Идёт ли корзина в счётчик «новых colo» для правила остановки.
    public var countsAsFreshColo: Bool { self == .freshColo }

    public var title: String {
        switch self {
        case .freshColo: return "Новая colo + HTTPS"
        case .sameColoNewAddress: return "Та же colo, другой адрес"
        case .unknownColo: return "HTTPS ok, colo неизвестна"
        case .ruColo: return "RU colo (штраф)"
        case .httpsFailed: return "HTTPS не работает"
        }
    }

    public var shortTitle: String {
        switch self {
        case .freshColo: return "новая colo"
        case .sameColoNewAddress: return "та же colo"
        case .unknownColo: return "colo ?"
        case .ruColo: return "RU colo"
        case .httpsFailed: return "HTTPS fail"
        }
    }
}

/// Почему кандидат признан нерабочим (есть доказательство отказа).
public enum CandidateRejectionReason: Sendable, Equatable {
    case sessionStartFailed(String)
    case handshakeTimeout
    case handshakeFailed(String)
    case rttProbesAllLost(attempted: Int)
    case rttProbesIncomplete(attempted: Int, reported: Int)
    case httpsFailed(String)
    case httpsTimedOut
    case cancelled
    case deadlineExceeded

    public var message: String {
        switch self {
        case .sessionStartFailed(let reason):
            return "Не удалось поднять тестовый туннель: \(reason)"
        case .handshakeTimeout:
            return "Handshake не подтверждён за отведённое время."
        case .handshakeFailed(let reason):
            return "Handshake не состоялся: \(reason)"
        case .rttProbesAllLost(let attempted):
            return "Все \(attempted) RTT-пробы через туннель потеряны."
        case .rttProbesIncomplete(let attempted, let reported):
            return "Драйвер выполнил \(reported) из \(attempted) RTT-проб."
        case .httpsFailed(let reason):
            return "HTTPS через туннель не работает: \(reason)"
        case .httpsTimedOut:
            return "HTTPS-проба через туннель не уложилась в таймаут."
        case .cancelled:
            return "Проверка отменена."
        case .deadlineExceeded:
            return "Дедлайн прогона истёк."
        }
    }
}

/// Почему кандидат не проверен до конца (доказательств нет ни за, ни против).
public enum CandidateUnverifiedReason: Sendable, Equatable {
    case httpsProbeUnsupported(String)
    case rttProbeUnsupported(String)
    case evidenceNotThroughTunnel(String)
    case incompleteEvidence(String)
    case driverContractViolation(String)
    case cancelled
    case deadlineExceeded

    public var message: String {
        switch self {
        case .httpsProbeUnsupported(let reason):
            return "HTTPS-проба через туннель недоступна: \(reason)"
        case .rttProbeUnsupported(let reason):
            return "RTT-проба через туннель недоступна: \(reason)"
        case .evidenceNotThroughTunnel(let reason):
            return "Доказательство снято вне туннеля и не учитывается: \(reason)"
        case .incompleteEvidence(let reason):
            return "Недостаточно доказательств: \(reason)"
        case .driverContractViolation(let reason):
            return "Драйвер нарушил контракт: \(reason)"
        case .cancelled:
            return "Проверка отменена до получения доказательств."
        case .deadlineExceeded:
            return "Дедлайн истёк до получения доказательств."
        }
    }

    public var isCancellationLike: Bool {
        switch self {
        case .cancelled, .deadlineExceeded: return true
        default: return false
        }
    }
}

public enum CandidateStatus: Sendable, Equatable {
    /// Кандидат доказанно работает; присвоена корзина.
    case confirmed(CandidateBucket)
    /// Кандидат доказанно не работает.
    case rejected(CandidateRejectionReason)
    /// Проверить не удалось (не путать с отказом); успехом не считается.
    case unverified(CandidateUnverifiedReason)

    public var bucket: CandidateBucket? {
        if case .confirmed(let bucket) = self { return bucket }
        return nil
    }

    public var isConfirmed: Bool { bucket != nil }

    public var rejection: CandidateRejectionReason? {
        if case .rejected(let reason) = self { return reason }
        return nil
    }

    public var unverified: CandidateUnverifiedReason? {
        if case .unverified(let reason) = self { return reason }
        return nil
    }

    public var isUnverified: Bool { unverified != nil }

    public var allowsDialing: Bool { isConfirmed && bucket != .httpsFailed }

    public var title: String {
        switch self {
        case .confirmed(let bucket): return bucket.title
        case .rejected(let reason): return reason.message
        case .unverified(let reason): return reason.message
        }
    }
}

// MARK: - Результат по кандидату

/// Полный результат проверки одного кандидата: сырые доказательства + вывод.
public struct CandidateValidation: Sendable, Equatable, Identifiable {
    /// 1-based номер попытки в прогоне.
    public let index: Int
    public let target: CandidateTarget
    public let status: CandidateStatus
    public let handshake: HandshakeOutcome?
    public let rtt: RTTProbeReport?
    public let https: WarpHTTPSProbe?
    /// colo, определённая по trace (upper-case), если была.
    public let colo: String?
    /// RTT для ранжирования: медиана проб (или время handshake) + RU-штраф.
    public let rankedRTTMs: Double?
    public let startedAt: Date
    public let durationMs: Double

    public init(index: Int,
                target: CandidateTarget,
                status: CandidateStatus,
                handshake: HandshakeOutcome?,
                rtt: RTTProbeReport?,
                https: WarpHTTPSProbe?,
                colo: String?,
                rankedRTTMs: Double?,
                startedAt: Date,
                durationMs: Double) {
        self.index = index
        self.target = target
        self.status = status
        self.handshake = handshake
        self.rtt = rtt
        self.https = https
        self.colo = colo
        self.rankedRTTMs = rankedRTTMs
        self.startedAt = startedAt
        self.durationMs = durationMs
    }

    public var id: Int { index }
    public var bucket: CandidateBucket? { status.bucket }
    public var displayEndpoint: String { target.endpointString }

    public var medianRTTMs: Double? { rtt?.medianRTTMs }
    public var lossFraction: Double { rtt?.lossFraction ?? 1.0 }
    public var lossPercentage: Double { lossFraction * 100.0 }

    /// Handshake подтверждён данными ядра.
    public var isAlive: Bool { handshake != nil }
    /// HTTPS-запрос реально прошёл через туннель и вернул 2xx.
    public var httpsReachable: Bool { https?.isEvidenceValid ?? false }
    /// Можно ли предлагать кандидата пользователю как рабочий.
    public var isUsable: Bool { status.allowsDialing }

    public var evidenceSummary: String {
        if let rejection = status.rejection { return rejection.message }
        if let unverified = status.unverified { return unverified.message }
        let rttText = medianRTTMs.map { String(format: "%.0f мс", $0) } ?? "RTT ?"
        let lossText = rtt.map { _ in String(format: "потери %.0f%%", lossPercentage) } ?? "потери ?"
        return "\(rttText), \(lossText), colo \(colo ?? "?")"
    }
}

// MARK: - События прогресса и остановка

public enum CandidateValidatorEvent: Sendable, Equatable {
    case started(totalCandidates: Int, plan: ValidationPlanSummary)
    case driverUnavailable(reason: String)
    case candidateStarted(index: Int, target: CandidateTarget)
    case handshakeObserved(index: Int, target: CandidateTarget, outcome: HandshakeOutcome)
    case rttMeasured(index: Int, target: CandidateTarget, report: RTTProbeReport)
    case httpsMeasured(index: Int, target: CandidateTarget, probe: WarpHTTPSProbe)
    case candidateFinished(CandidateValidation)
    case freshColoDiscovered(colo: String, freshCount: Int, target: CandidateTarget)
    case candidateCancelled(index: Int, target: CandidateTarget)
    case finished(report: ValidationReport)

    public var index: Int? {
        switch self {
        case .candidateStarted(let index, _),
             .handshakeObserved(let index, _, _),
             .rttMeasured(let index, _, _),
             .httpsMeasured(let index, _, _),
             .candidateCancelled(let index, _):
            return index
        case .candidateFinished(let validation):
            return validation.index
        case .started, .driverUnavailable, .freshColoDiscovered, .finished:
            return nil
        }
    }
}

/// Причина завершения прогона.
public enum ValidationStopReason: Sendable, Equatable {
    case allCandidatesTested
    case freshColoLimitReached(limit: Int, colos: [String])
    case attemptLimitReached(limit: Int)
    case deadlineReached(seconds: Double)
    case cancelled
    case driverUnavailable(String)

    public var message: String {
        switch self {
        case .allCandidatesTested:
            return "Проверены все кандидаты."
        case .freshColoLimitReached(let limit, let colos):
            return "Найдено \(limit) новых colo (\(colos.joined(separator: ", "))) — перебор остановлен."
        case .attemptLimitReached(let limit):
            return "Достигнут лимит попыток (\(limit))."
        case .deadlineReached(let seconds):
            return "Истёк дедлайн прогона (\(Int(seconds)) с)."
        case .cancelled:
            return "Прогон отменён."
        case .driverUnavailable(let reason):
            return "Проверка недоступна: \(reason)"
        }
    }
}

// MARK: - Отчёт

public struct ValidationReport: Sendable, Equatable {
    public let startedAt: Date
    public let finishedAt: Date
    public let availability: TunnelTestDriverAvailability
    public let capabilities: TunnelTestCapabilities?
    public let plan: ValidationPlanSummary
    /// Все попытки в порядке выполнения (включая отказы и unverified).
    public let validations: [CandidateValidation]
    /// Только доказанно рабочие, отсортированные по качеству.
    public let ranked: [CandidateValidation]
    /// Новые colo в порядке обнаружения.
    public let freshColos: [String]
    public let stopReason: ValidationStopReason

    public init(startedAt: Date,
                finishedAt: Date,
                availability: TunnelTestDriverAvailability,
                capabilities: TunnelTestCapabilities?,
                plan: ValidationPlanSummary,
                validations: [CandidateValidation],
                ranked: [CandidateValidation],
                freshColos: [String],
                stopReason: ValidationStopReason) {
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.availability = availability
        self.capabilities = capabilities
        self.plan = plan
        self.validations = validations
        self.ranked = ranked
        self.freshColos = freshColos
        self.stopReason = stopReason
    }

    public var best: CandidateValidation? { ranked.first }
    public var confirmed: [CandidateValidation] { validations.filter { $0.status.isConfirmed } }
    public var rejected: [CandidateValidation] { validations.filter { $0.status.rejection != nil } }
    public var unverified: [CandidateValidation] { validations.filter { $0.status.isUnverified } }

    public var attemptedCount: Int { validations.count }
    public var duration: TimeInterval { finishedAt.timeIntervalSince(startedAt) }

    /// Отчёт можно считать результативным только если драйвер был доступен
    /// и есть хотя бы один доказанно рабочий кандидат.
    public var isActionable: Bool {
        guard availability.isAvailable else { return false }
        return !ranked.isEmpty
    }

    /// Драйвер доступен, но HTTPS-проверку сделать не может: кандидаты
    /// остаются `.unverified`, и это НЕ успех.
    public var isInconclusiveButAvailable: Bool {
        availability.isAvailable && ranked.isEmpty && !unverified.isEmpty
    }
}

// MARK: - Прогресс

/// Broadcaster прогресса: любое число подписчиков на `AsyncStream`.
public final class ValidationProgress: @unchecked Sendable {
    private let lock = NSLock()
    private var continuations: [UUID: AsyncStream<CandidateValidatorEvent>.Continuation] = [:]
    private var finished = false

    public init() {}

    /// Создаёт новый поток событий. Подписываться нужно до старта прогона,
    /// иначе ранние события будут потеряны (буферизуется только «хвост»).
    public func makeStream(
        bufferingPolicy: AsyncStream<CandidateValidatorEvent>.Continuation.BufferingPolicy = .bufferingNewest(512)
    ) -> AsyncStream<CandidateValidatorEvent> {
        let identifier = UUID()
        let (stream, continuation) = AsyncStream.makeStream(of: CandidateValidatorEvent.self,
                                                            bufferingPolicy: bufferingPolicy)
        continuation.onTermination = { [weak self] _ in
            guard let self else { return }
            self.lock.lock()
            self.continuations.removeValue(forKey: identifier)
            self.lock.unlock()
        }
        lock.lock()
        if finished {
            lock.unlock()
            continuation.finish()
        } else {
            continuations[identifier] = continuation
            lock.unlock()
        }
        return stream
    }

    func yield(_ event: CandidateValidatorEvent) {
        lock.lock()
        let active = Array(continuations.values)
        lock.unlock()
        for continuation in active {
            continuation.yield(event)
        }
    }

    func finish() {
        lock.lock()
        finished = true
        let active = Array(continuations.values)
        continuations.removeAll()
        lock.unlock()
        for continuation in active {
            continuation.finish()
        }
    }
}

// MARK: - Валидатор

/// Последовательный валидатор кандидатов.
///
/// Использование (app-слой):
/// ```swift
/// let progress = ValidationProgress()
/// let stream = progress.makeStream()
/// let validator = CandidateValidator(driver: appDriver, progress: progress)
/// Task { for await event in stream { ... } }
/// let report = await validator.validate(targets: targets, baseConfiguration: warpConfig)
/// ```
public actor CandidateValidator {
    public let configuration: ValidationConfiguration
    public let progress: ValidationProgress?

    private let driver: any TunnelTestDriving
    private var stopRequested = false
    private var activeSession: (any TunnelTestSession)?

    public init(configuration: ValidationConfiguration = ValidationConfiguration(),
                driver: any TunnelTestDriving,
                progress: ValidationProgress? = nil) {
        self.configuration = configuration
        self.driver = driver
        self.progress = progress
    }

    /// Внешняя просьба остановиться: текущий тестовый туннель будет погашен
    /// после завершения текущего шага, прогон вернёт частичный отчёт.
    public func requestStop() {
        stopRequested = true
    }

    /// Проверяет кандидатов из `EndpointScout`.
    public func validate(endpoints: [EndpointCandidate],
                         baseConfiguration: WarpConfig) async -> ValidationReport {
        let targets = endpoints.compactMap { CandidateTarget($0) }
        return await validate(targets: targets, baseConfiguration: baseConfiguration)
    }

    /// Основной вход: `targets` уже нормализованы и упорядочены внешним scout'ом.
    public func validate(targets: [CandidateTarget],
                         baseConfiguration: WarpConfig) async -> ValidationReport {
        let startedAt = Date()
        let deadline = Date().addingTimeInterval(configuration.maxDuration)
        let availability = driver.availability
        let capabilities = availability.capabilities

        progress?.yield(.started(totalCandidates: min(targets.count, configuration.maxAttempts),
                                 plan: configuration.planSummary))

        guard availability.isAvailable else {
            let reason = availability.unavailableReason ?? "причина не указана"
            progress?.yield(.driverUnavailable(reason: reason))
            let report = ValidationReport(startedAt: startedAt,
                                          finishedAt: Date(),
                                          availability: availability,
                                          capabilities: nil,
                                          plan: configuration.planSummary,
                                          validations: [],
                                          ranked: [],
                                          freshColos: [],
                                          stopReason: .driverUnavailable(reason))
            progress?.yield(.finished(report: report))
            progress?.finish()
            return report
        }

        var validations: [CandidateValidation] = []
        var freshColos: [String] = []
        var knownColos = Set<String>()
        var attemptedTargets = Set<CandidateTarget>()
        var stopReason: ValidationStopReason = .allCandidatesTested
        var index = 0

        func isFresh(_ colo: String) -> Bool {
            !knownColos.contains(colo)
        }

        loop: for target in targets {
            if stopRequested || Task.isCancelled {
                stopReason = .cancelled
                break loop
            }
            if Date() >= deadline {
                stopReason = .deadlineReached(seconds: configuration.maxDuration)
                break loop
            }
            if attemptedTargets.contains(target) { continue }
            if validations.count >= configuration.maxAttempts {
                stopReason = .attemptLimitReached(limit: configuration.maxAttempts)
                break loop
            }

            index += 1
            attemptedTargets.insert(target)
            progress?.yield(.candidateStarted(index: index, target: target))

            let candidateStart = Date()
            let candidateClock = WarpMonotonicClock.now()
            let request = TestTunnelRequest(configuration: baseConfiguration,
                                            target: target,
                                            handshakeTimeout: configuration.handshakeTimeout,
                                            rttPlan: configuration.rttPlan,
                                            httpsPlan: configuration.httpsPlan,
                                            restoreProductionTunnel: configuration.restoreProductionTunnel)

            var session: (any TunnelTestSession)?
            var handshake: HandshakeOutcome?
            var rttReport: RTTProbeReport?
            var httpsProbe: WarpHTTPSProbe?
            var status: CandidateStatus?
            var colo: String?
            // RTT может быть недоступен как возможность движка; это не приговор
            // кандидату, поэтому HTTPS-пробу всё равно пробуем.
            var rttUnsupportedReason: String?

            do {
                session = try await driver.startTestSession(request)
                activeSession = session

                // 1. Handshake глазами ядра (до 8 с по умолчанию).
                let outcome = try await session!.waitForHandshake(timeout: configuration.handshakeTimeout)
                handshake = outcome
                progress?.yield(.handshakeObserved(index: index, target: target, outcome: outcome))

                // 2. Три RTT-пробы через туннель.
                let rttOutcome = await session!.probeRTT(configuration.rttPlan)
                switch rttOutcome {
                case .measured(let report):
                    if report.attempted != configuration.rttPlan.attempts {
                        status = .unverified(.driverContractViolation(
                            "RTT: запрошено \(configuration.rttPlan.attempts), выполнено \(report.attempted)"))
                    } else if !report.isComplete {
                        status = .rejected(.rttProbesIncomplete(attempted: report.attempted,
                                                               reported: report.samples.count))
                    } else if report.samples.isEmpty {
                        status = .rejected(.rttProbesAllLost(attempted: report.attempted))
                    } else {
                        rttReport = report
                        progress?.yield(.rttMeasured(index: index, target: target, report: report))
                    }
                case .unsupported(let reason):
                    rttUnsupportedReason = reason
                case .cancelled:
                    status = .unverified(.cancelled)
                }

                // 3. HTTPS через туннель (cdn-cgi/trace).
                if status == nil {
                    let httpsOutcome = await session!.probeHTTPS(configuration.httpsPlan)
                    switch httpsOutcome {
                    case .completed(let probe):
                        httpsProbe = probe
                        progress?.yield(.httpsMeasured(index: index, target: target, probe: probe))
                        status = Self.status(for: probe, configuration: configuration, knownColos: knownColos)
                        colo = probe.colo
                    case .failed(let reason):
                        status = .rejected(.httpsFailed(reason))
                    case .timedOut:
                        status = .rejected(.httpsTimedOut)
                    case .unsupported(let reason):
                        // HTTPS не проверить: это unverified, а НЕ успех.
                        if let rttUnsupportedReason {
                            status = .unverified(.httpsProbeUnsupported(
                                "\(reason); RTT-проба тоже недоступна: \(rttUnsupportedReason)"))
                        } else {
                            status = .unverified(.httpsProbeUnsupported(reason))
                        }
                    case .cancelled:
                        status = .unverified(.cancelled)
                    }
                }

                if Task.isCancelled {
                    status = .unverified(.cancelled)
                }
            } catch let error as WarpEngineError {
                if case .cancelled = error {
                    status = .unverified(.cancelled)
                } else if error.isCapabilityFailure {
                    // Движок/драйвер в принципе не может поднять туннель:
                    // это не «кандидат плохой», а недоступность проверки.
                    await session?.stop()
                    activeSession = nil
                    let reason = error.errorDescription ?? "движок недоступен"
                    progress?.yield(.driverUnavailable(reason: reason))
                    stopReason = .driverUnavailable(reason)
                    break loop
                } else {
                    switch error {
                    case .handshakeTimeout:
                        status = .rejected(.handshakeTimeout)
                    case .handshakeFailed(let reason):
                        status = .rejected(.handshakeFailed(reason))
                    case .configurationRejected(let reason):
                        status = .rejected(.sessionStartFailed(reason))
                    default:
                        status = .rejected(.sessionStartFailed(error.errorDescription ?? "ошибка движка"))
                    }
                }
            } catch is CancellationError {
                status = .unverified(.cancelled)
            } catch {
                status = .rejected(.sessionStartFailed(error.localizedDescription))
            }

            if Task.isCancelled || stopRequested, status == nil {
                status = .unverified(.cancelled)
            }

            let resolvedStatus = status ?? .unverified(.incompleteEvidence("проверка не завершена"))
            let rankedRTT = Self.rankedRTT(handshake: handshake,
                                           rtt: rttReport,
                                           status: resolvedStatus,
                                           configuration: configuration)
            let validation = CandidateValidation(index: index,
                                                 target: target,
                                                 status: resolvedStatus,
                                                 handshake: handshake,
                                                 rtt: rttReport,
                                                 https: httpsProbe,
                                                 colo: colo,
                                                 rankedRTTMs: rankedRTT,
                                                 startedAt: candidateStart,
                                                 durationMs: WarpMonotonicClock.millisecondsSince(candidateClock))
            validations.append(validation)
            progress?.yield(.candidateFinished(validation))

            // Учёт новых colo для правила остановки.
            if let bucket = resolvedStatus.bucket, bucket.countsAsFreshColo, let colo, !colo.isEmpty {
                let fresh = isFresh(colo)
                knownColos.insert(colo)
                if fresh {
                    freshColos.append(colo)
                    progress?.yield(.freshColoDiscovered(colo: colo,
                                                         freshCount: freshColos.count,
                                                         target: target))
                }
            } else if let bucket = resolvedStatus.bucket, bucket == .ruColo,
                      configuration.countRUColosAsFresh, let colo, !colo.isEmpty {
                if isFresh(colo) {
                    freshColos.append(colo)
                    progress?.yield(.freshColoDiscovered(colo: colo,
                                                         freshCount: freshColos.count,
                                                         target: target))
                }
                knownColos.insert(colo)
            } else if let bucket = resolvedStatus.bucket, bucket != .httpsFailed, let colo, !colo.isEmpty {
                // bucket 2/3/4: colo встречалась или не идёт в счётчик, но
                // запоминаем её, чтобы классификация следующих была верной.
                knownColos.insert(colo)
            }

            // Гасим тестовый туннель до следующего кандидата.
            await session?.stop()
            activeSession = nil

            let reachedFreshLimit = freshColos.count >= configuration.stopAfterFreshColos
            if reachedFreshLimit {
                stopReason = .freshColoLimitReached(limit: configuration.stopAfterFreshColos,
                                                    colos: freshColos)
                break loop
            }
            if Task.isCancelled || stopRequested {
                stopReason = .cancelled
                break loop
            }
            if Date() >= deadline {
                stopReason = .deadlineReached(seconds: configuration.maxDuration)
                break loop
            }
            if validations.count < min(targets.count, configuration.maxAttempts),
               configuration.pauseBetweenCandidates > 0 {
                do {
                    try await Task.sleep(nanoseconds: UInt64(configuration.pauseBetweenCandidates * 1_000_000_000))
                } catch {
                    stopReason = .cancelled
                    break loop
                }
            }
        }

        // На всякий случай: если остался поднятым тестовый туннель — гасим.
        if let leftoverSession = activeSession {
            await leftoverSession.stop()
            activeSession = nil
        }

        if Task.isCancelled, stopReason != .cancelled {
            stopReason = .cancelled
        }

        let ranked = Self.rank(validations, configuration: configuration)
        let report = ValidationReport(startedAt: startedAt,
                                      finishedAt: Date(),
                                      availability: availability,
                                      capabilities: capabilities,
                                      plan: configuration.planSummary,
                                      validations: validations,
                                      ranked: ranked,
                                      freshColos: freshColos,
                                      stopReason: stopReason)
        progress?.yield(.finished(report: report))
        progress?.finish()
        return report
    }

    // MARK: - Классификация (чистые функции, пригодны для тестов)

    /// Классифицирует успешный HTTPS-ответ (HTTP 2xx) по корзинам.
    ///
    /// - `viaTunnel == false` → unverified: ответ вне туннеля ничего не доказывает.
    /// - нет trace/colo → bucket 3 (unknown colo), а не выдуманная colo.
    /// - colo из RU-списка → bucket 4.
    /// - colo впервые в прогоне → bucket 1, иначе → bucket 2.
    public static func status(for probe: WarpHTTPSProbe,
                              configuration: ValidationConfiguration,
                              knownColos: Set<String>) -> CandidateStatus {
        guard probe.viaTunnel else {
            return .unverified(.evidenceNotThroughTunnel("HTTPS-ответ получен вне тестового туннеля"))
        }
        guard probe.isHTTPOK else {
            return .rejected(.httpsFailed("HTTP \(probe.httpStatus)"))
        }
        guard let colo = probe.colo, !colo.isEmpty else {
            return .confirmed(.unknownColo)
        }
        return .confirmed(bucket(forColo: colo,
                                 knownColos: knownColos,
                                 configuration: configuration))
    }

    /// Корзина по colo и уже встреченным colo прогона.
    public static func bucket(forColo colo: String,
                              knownColos: Set<String>,
                              configuration: ValidationConfiguration) -> CandidateBucket {
        let normalized = (WarpTrace.normalizeColo(colo) ?? colo).uppercased()
        if configuration.ruColos.contains(normalized) {
            return .ruColo
        }
        if knownColos.contains(normalized) {
            return .sameColoNewAddress
        }
        return .freshColo
    }

    /// RTT для ранжирования: медиана проб, иначе длительность handshake.
    /// RU colo получает штраф.
    public static func rankedRTT(handshake: HandshakeOutcome?,
                                 rtt: RTTProbeReport?,
                                 status: CandidateStatus,
                                 configuration: ValidationConfiguration) -> Double? {
        let base = rtt?.medianRTTMs ?? handshake?.attemptDurationMs
        guard let base else { return nil }
        let penalty = status.bucket == .ruColo ? configuration.ruColoPenaltyMs : 0
        return base + penalty
    }

    /// Ранжирование подтверждённых кандидатов.
    ///
    /// Порядок: корзина (1 → 4) → RTT с учётом штрафа → потери → время
    /// handshake → адрес (для детерминированности). Никакие `.unverified` и
    /// `.rejected` в рейтинг не попадают.
    public static func rank(_ validations: [CandidateValidation],
                            configuration: ValidationConfiguration) -> [CandidateValidation] {
        validations
            .filter { $0.status.isConfirmed }
            .sorted { lhs, rhs in
                let lhsBucket = lhs.bucket?.rawValue ?? Int.max
                let rhsBucket = rhs.bucket?.rawValue ?? Int.max
                if lhsBucket != rhsBucket { return lhsBucket < rhsBucket }

                let lhsRTT = lhs.rankedRTTMs ?? .infinity
                let rhsRTT = rhs.rankedRTTMs ?? .infinity
                if lhsRTT != rhsRTT { return lhsRTT < rhsRTT }

                let lhsLoss = lhs.lossFraction
                let rhsLoss = rhs.lossFraction
                if lhsLoss != rhsLoss { return lhsLoss < rhsLoss }

                let lhsHandshake = lhs.handshake?.attemptDurationMs ?? .infinity
                let rhsHandshake = rhs.handshake?.attemptDurationMs ?? .infinity
                if lhsHandshake != rhsHandshake { return lhsHandshake < rhsHandshake }

                return lhs.target < rhs.target
            }
    }
}

// MARK: - Сверка с Shared/EndpointScout.swift

extension CandidateTarget {
    /// Единственная точка сверки с моделью scout'а.
    ///
    /// Если `EndpointCandidate` в `Shared/` называется/устроен иначе, правится
    /// только этот инициализатор — валидатор работает с `CandidateTarget`.
    public init?(_ candidate: EndpointCandidate) {
        guard !candidate.host.isEmpty, candidate.port != 0 else { return nil }
        self.init(host: candidate.host, port: candidate.port)
    }
}
