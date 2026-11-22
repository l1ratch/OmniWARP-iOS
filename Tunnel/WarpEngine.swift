//
//  WarpEngine.swift
//  OmniWARP — Tunnel
//
//  Контракты движка WARP/AmneziaWG и данных, собранных при проверке кандидатов.
//
//  Зачем отдельный слой
//  --------------------
//  UI и логика подбора endpoints не должны знать, чем именно поднимается туннель:
//  userspace-ядром amneziawg-go (через WireGuardKit, статически слинкованный
//  `libwg-go.a`), тестовым туннелем на уровне приложения или чем-то ещё.
//  Здесь описаны только протоколы и value-типы. Реальные адаптеры:
//    * `Tunnel/AmneziaWGCoreAdapter.swift` — честный boundary к userspace-ядру
//      (`#if canImport(WireGuardKit)`), по умолчанию `.unavailable`;
//    * App-слой реализует `TunnelTestDriving` для HTTPS-проверки через туннель
//      (URLSession при поднятом тестовом туннеле с default route).
//
//  Ключевое правило (анти-fake-success)
//  ------------------------------------
//  Движок/драйвер обязан отличать «не смог проверить» от «проверил и работает».
//  Любая невозможность измерения возвращается как `.unsupported(...)`,
//  `.unavailable(...)` или `.failed(...)`, а НЕ как успех. `HTTPSProbeOutcome`
//  дополнительно фиксирует `viaTunnel`: ответ, снятый вне туннеля, не является
//  доказательством работоспособности кандидата.
//
//  Ограничения iOS, из-за которых API именно такой
//  ------------------------------------------------
//  1. iOS не позволяет двум `NEPacketTunnelProvider` работать одновременно.
//     Полный тест кандидата — последовательный: поднять тестовый туннель,
//     проверить, погасить, восстановить продовый конфиг. Параллельный перебор
//     невозможен, и этот файл его не обещает.
//  2. Сокеты самого Network Extension обходят его собственный туннель.
//     Поэтому HTTPS-проба «через туннель» из extension невозможна без
//     userspace-netstack; в extension-адаптере она честно `.unsupported`,
//     а рабочая реализация живёт на уровне app (`TunnelTestDriving`).
//  3. Сырой ICMP-сокет недоступен. RTT меряется UDP/TCP-пробами через туннель
//     (см. `RTTProbePlan`), а не ping'ом.
//

import Foundation
import Dispatch

// MARK: - Ошибки

/// Ошибки движка. Отдельно выделено «физически не умею» (capability failure),
/// чтобы вызывающий код не путал это с «кандидат не прошёл проверку».
public enum WarpEngineError: Error, LocalizedError, Equatable {
    /// Ядро не подключено/не слинковано в бинарь.
    case engineUnavailable(String)
    /// Движок в неподходящем состоянии (start поверх start, stop без start).
    case invalidState(String)
    /// Ядро отвергло конфигурацию (невалидные ключи, AWG-параметры, endpoint).
    case configurationRejected(String)
    /// Handshake не наблюдён за отведённый таймаут.
    case handshakeTimeout
    /// Handshake не состоялся по явной причине (ошибка ядра, peer отверг ключ).
    case handshakeFailed(String)
    /// Нет user-space пути данных внутри туннеля (нет netstack / инъекции пакетов).
    case dataPathUnavailable(String)
    /// Возможность не поддерживается движком для данного контекста (например,
    /// HTTPS-проба из extension).
    case capabilityUnavailable(String)
    /// Операция отменена вызывающей стороной.
    case cancelled
    /// Проба превысила локальный таймаут.
    case probeTimedOut
    /// Реализация драйвера нарушила контракт (вернула противоречивые данные).
    case contractViolation(String)

    public var errorDescription: String? {
        switch self {
        case .engineUnavailable(let reason):
            return "Ядро AmneziaWG недоступно: \(reason)"
        case .invalidState(let reason):
            return "Движок в неподходящем состоянии: \(reason)"
        case .configurationRejected(let reason):
            return "Ядро отвергло конфигурацию: \(reason)"
        case .handshakeTimeout:
            return "Handshake не подтверждён за отведённое время."
        case .handshakeFailed(let reason):
            return "Handshake не состоялся: \(reason)"
        case .dataPathUnavailable(let reason):
            return "Путь данных внутри туннеля недоступен: \(reason)"
        case .capabilityUnavailable(let reason):
            return "Возможность недоступна: \(reason)"
        case .cancelled:
            return "Проверка отменена."
        case .probeTimedOut:
            return "Проба не уложилась в таймаут."
        case .contractViolation(let reason):
            return "Драйвер вернул противоречивые данные: \(reason)"
        }
    }

    /// `true` для случаев «этот движок в принципе не умеет операцию»,
    /// а не «конкретный кандидат оказался плохим».
    public var isCapabilityFailure: Bool {
        switch self {
        case .engineUnavailable, .dataPathUnavailable, .capabilityUnavailable:
            return true
        case .invalidState, .configurationRejected, .handshakeTimeout, .handshakeFailed,
             .cancelled, .probeTimedOut, .contractViolation:
            return false
        }
    }
}

// MARK: - Backend и доступность

/// Описание подключённого ядра/бэкенда.
public struct WarpEngineBackend: Sendable, Equatable {
    /// Например `"amneziawg-go (WireGuardKit)"`.
    public let identifier: String
    /// Умеет ли движок мерить RTT внутри туннеля.
    public let inTunnelRTT: Bool
    /// Умеет ли движок выполнять HTTPS-пробу внутри туннеля.
    public let inTunnelHTTPS: Bool

    public init(identifier: String, inTunnelRTT: Bool, inTunnelHTTPS: Bool) {
        self.identifier = identifier
        self.inTunnelRTT = inTunnelRTT
        self.inTunnelHTTPS = inTunnelHTTPS
    }
}

/// Доступность движка. Возвращается синхронно и дёшево.
public enum WarpEngineAvailability: Sendable, Equatable {
    case available(WarpEngineBackend)
    /// Явная причина, которую можно показать пользователю (RU).
    case unavailable(String)

    public var backend: WarpEngineBackend? {
        if case .available(let backend) = self { return backend }
        return nil
    }

    public var isAvailable: Bool { backend != nil }

    public var unavailableReason: String? {
        if case .unavailable(let reason) = self { return reason }
        return nil
    }
}

// MARK: - Статистика

/// Снимок счётчиков ядра. Для extension-адаптера источник —
/// `WireGuardAdapter.getRuntimeConfiguration()` (UAPI: `rx_bytes`, `tx_bytes`,
/// `last_handshake_time_sec`/`nsec`), а не собственная бухгалтерия.
public struct WarpEngineStats: Sendable, Equatable {
    public let sampledAt: Date
    public let rxBytes: UInt64
    public let txBytes: UInt64
    public let lastHandshakeAt: Date?
    /// `host:port` peer'а, если ядро его отдаёт.
    public let endpoint: String?

    public init(sampledAt: Date = Date(),
                rxBytes: UInt64,
                txBytes: UInt64,
                lastHandshakeAt: Date?,
                endpoint: String?) {
        self.sampledAt = sampledAt
        self.rxBytes = rxBytes
        self.txBytes = txBytes
        self.lastHandshakeAt = lastHandshakeAt
        self.endpoint = endpoint
    }
}

// MARK: - Handshake

/// Откуда взято доказательство handshake. Значение важно: handshake по UAPI
/// (`last_handshake_time_sec`) — это факт от ядра, телеметрия движка — косвенная
/// информация, и в отчёте она помечается отдельно.
public enum HandshakeEvidenceSource: String, Sendable, Equatable {
    /// UAPI-выгрузка ядра: реальный `last_handshake_time_sec`.
    case runtimeConfiguration
    /// Собственная телеметрия движка (счётчики/события адаптера).
    case engineTelemetry
}

/// Подтверждённый handshake.
public struct HandshakeOutcome: Sendable, Equatable {
    /// Момент, когда handshake был обнаружен (монотонная шкала).
    public let observedAt: Date
    /// Абсолютная метка из ядра (`last_handshake_time_sec`).
    public let lastHandshakeAt: Date
    /// Сколько времени прошло от старта попытки до обнаружения handshake.
    public let attemptDurationMs: Double
    public let source: HandshakeEvidenceSource
    public let rxBytes: UInt64
    public let txBytes: UInt64

    public init(observedAt: Date,
                lastHandshakeAt: Date,
                attemptDurationMs: Double,
                source: HandshakeEvidenceSource,
                rxBytes: UInt64,
                txBytes: UInt64) {
        self.observedAt = observedAt
        self.lastHandshakeAt = lastHandshakeAt
        self.attemptDurationMs = attemptDurationMs
        self.source = source
        self.rxBytes = rxBytes
        self.txBytes = txBytes
    }
}

// MARK: - Кандидат

/// Нормализованное описание проверяемой точки входа (`endpoint`).
///
/// Отдельный тип нужен, чтобы валидатор не зависел от точной формы
/// `EndpointCandidate` из `Shared/EndpointScout.swift`: конвертация выполняется
/// в одном месте (`CandidateTarget.init?(_:)` в `CandidateValidator.swift`).
public struct CandidateTarget: Hashable, Sendable, Equatable, Comparable {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    /// Парсит `host:port` и `[ipv6]:port`.
    public init?(endpoint: String) {
        let trimmed = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let host: String
        let portPart: String
        if trimmed.hasPrefix("[") {
            guard let close = trimmed.firstIndex(of: "]") else { return nil }
            let afterClose = trimmed.index(after: close)
            guard afterClose < trimmed.endIndex, trimmed[afterClose] == ":" else { return nil }
            host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
            portPart = String(trimmed[trimmed.index(after: afterClose)...])
        } else {
            guard let colon = trimmed.lastIndex(of: ":") else { return nil }
            host = String(trimmed[trimmed.startIndex..<colon])
            portPart = String(trimmed[trimmed.index(after: colon)...])
        }

        guard !host.isEmpty, let port = UInt16(portPart) else { return nil }
        self.init(host: host, port: port)
    }

    public var endpointString: String {
        // IPv6-литерал в конфиге WireGuard пишется в скобках.
        if host.contains(":") { return "[\(host)]:\(port)" }
        return "\(host):\(port)"
    }

    public var isIPv6Literal: Bool { host.contains(":") }

    public var isPrivateAddress: Bool {
        // Для оценки «RU colo» это не нужно, но пригодится вызывающему коду.
        let parts = host.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return false }
        switch (parts[0], parts[1]) {
        case (10, _), (127, _), (0, _): return true
        case (169, 254): return true
        case (172, 16...31): return true
        case (192, 168): return true
        default: return false
        }
    }

    public static func < (lhs: CandidateTarget, rhs: CandidateTarget) -> Bool {
        if lhs.host != rhs.host { return lhs.host < rhs.host }
        return lhs.port < rhs.port
    }
}

// MARK: - RTT-проба

/// Транспорт RTT-пробы. ICMP недоступен без raw-сокета, поэтому только UDP/TCP.
public enum RTTProbeTransport: String, Sendable, Equatable {
    case udp
    case tcp
}

public struct RTTProbePlan: Sendable, Equatable {
    /// По ТЗ — ровно 3 пробы. Драйвер обязан вернуть данные ровно по стольким
    /// attempt'ам (успех + потеря), иначе это нарушение контракта.
    public var attempts: Int
    /// Таймаут одного attempt'а.
    public var timeout: TimeInterval
    public var transport: RTTProbeTransport
    /// Полезная нагрузка UDP-пробы; для TCP используется как подсказка размеру
    /// буфера и в расчёте не участвует.
    public var payloadBytes: Int

    public init(attempts: Int = 3,
                timeout: TimeInterval = 2.0,
                transport: RTTProbeTransport = .udp,
                payloadBytes: Int = 32) {
        self.attempts = max(1, attempts)
        self.timeout = max(0.1, timeout)
        self.transport = transport
        self.payloadBytes = max(1, payloadBytes)
    }
}

public struct RTTProbeSample: Sendable, Equatable {
    /// 1-based номер попытки.
    public let round: Int
    public let rttMs: Double
    public let transport: RTTProbeTransport

    public init(round: Int, rttMs: Double, transport: RTTProbeTransport) {
        self.round = round
        self.rttMs = rttMs
        self.transport = transport
    }
}

/// Результат серии RTT-проб.
public struct RTTProbeReport: Sendable, Equatable {
    public let transport: RTTProbeTransport
    /// Сколько попыток драйвер реально выполнил (должно равняться плану).
    public let attempted: Int
    public let samples: [RTTProbeSample]
    /// Сколько попыток истекло по таймауту/ошибке.
    public let lost: Int

    public init(transport: RTTProbeTransport,
                attempted: Int,
                samples: [RTTProbeSample],
                lost: Int) {
        self.transport = transport
        self.attempted = attempted
        self.samples = samples
        self.lost = lost
    }

    public var medianRTTMs: Double? {
        let values = samples.map { $0.rttMs }
        return values.warpMedian
    }

    public var minRTTMs: Double? { samples.map { $0.rttMs }.min() }
    public var maxRTTMs: Double? { samples.map { $0.rttMs }.max() }

    /// Доля потерянных попыток, 0...1.
    public var lossFraction: Double {
        guard attempted > 0 else { return 1 }
        return min(1, max(0, Double(lost) / Double(attempted)))
    }

    /// Полнота отчёта: каждая попытка либо в `samples`, либо в `lost`.
    public var isComplete: Bool { samples.count + lost == attempted }

    public var isUsable: Bool { !samples.isEmpty }
}

public enum RTTProbeOutcome: Sendable, Equatable {
    case measured(RTTProbeReport)
    /// Движок не умеет мерить RTT внутри туннеля (нет пути данных).
    case unsupported(String)
    case cancelled

    public var report: RTTProbeReport? {
        if case .measured(let report) = self { return report }
        return nil
    }

    public var unsupportedReason: String? {
        if case .unsupported(let reason) = self { return reason }
        return nil
    }

    public var isCancelled: Bool {
        if case .cancelled = self { return true }
        return false
    }
}

// MARK: - HTTPS / cdn-cgi/trace

/// `https://www.cloudflare.com/cdn-cgi/trace` — точка получения colo.
public struct HTTPSProbePlan: Sendable, Equatable {
    public static let cloudflareTraceURL = URL(string: "https://www.cloudflare.com/cdn-cgi/trace")!

    public var url: URL
    public var timeout: TimeInterval
    /// Требовать ли разобранный trace. Без него colo неизвестна, но сам факт
    /// HTTPS всё равно остаётся доказательством работы пути данных.
    public var requireTrace: Bool

    public init(url: URL = HTTPSProbePlan.cloudflareTraceURL,
                timeout: TimeInterval = 10.0,
                requireTrace: Bool = true) {
        self.url = url
        self.timeout = max(0.5, timeout)
        self.requireTrace = requireTrace
    }
}

/// Разобранный ответ `/cdn-cgi/trace` (`key=value` построчно).
public struct WarpTrace: Sendable, Equatable {
    public let values: [String: String]

    public init(values: [String: String]) {
        self.values = values
    }

    /// Строгий парсер: только строки `key=value`. Возвращает `nil`, если в теле
    /// нет ни одного осмысленного ключа trace.
    public init?(body: String) {
        var parsed: [String: String] = [:]
        for rawLine in body.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            guard let separator = line.firstIndex(of: "=") else { continue }
            let key = String(line[line.startIndex..<separator])
                .trimmingCharacters(in: .whitespaces)
                .lowercased()
            let value = String(line[line.index(after: separator)...])
                .trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, key.count <= 32, value.count <= 512 else { continue }
            guard Self.recognisedKeys.contains(key) else { continue }
            parsed[key] = value
        }
        guard !parsed.isEmpty else { return nil }
        self.values = parsed
    }

    private static let recognisedKeys: Set<String> = [
        "fl", "h", "ip", "ts", "visit_scheme", "uag", "colo", "sliver",
        "http", "loc", "tls", "sni", "warp", "gateway", "rbi", "kex"
    ]

    /// Cloudflare colo (IATA), нормализованный (upper-case).
    public var colo: String? {
        let raw = values["colo"]
        return WarpTrace.normalizeColo(raw)
    }

    public var clientIP: String? {
        WarpTrace.sanitizedIP(values["ip"])
    }

    /// `on` / `off` / `plus` — включает ли соединение WARP.
    public var warp: String? {
        values["warp"]?.lowercased()
    }

    /// Двухбуквенный код страны (полезен для диагностики RU-маршрутов).
    public var location: String? {
        values["loc"]?.uppercased()
    }

    public var timestamp: String? { values["ts"] }

    public var isWARPTunneled: Bool {
        guard let warp else { return false }
        return warp == "on" || warp == "plus"
    }

    /// Приводит colo к канонному виду: trim, upper-case, только A–Z/0–9.
    public static func normalizeColo(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let cleaned = raw
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .uppercased()
            .filter { $0.isLetter || $0.isNumber }
        guard !cleaned.isEmpty, cleaned.count <= 8 else { return nil }
        return cleaned
    }

    private static func sanitizedIP(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 64 else { return nil }
        return trimmed
    }
}

/// Результат успешной HTTPS-пробы.
public struct WarpHTTPSProbe: Sendable, Equatable {
    public let url: URL
    public let httpStatus: Int
    public let durationMs: Double
    public let bodyBytes: Int
    public let trace: WarpTrace?
    /// `true` только если трафик пробы реально шёл внутри тестового туннеля.
    /// Ответ, снятый напрямую (в обход), доказательством не является.
    public let viaTunnel: Bool

    public init(url: URL,
                httpStatus: Int,
                durationMs: Double,
                bodyBytes: Int,
                trace: WarpTrace?,
                viaTunnel: Bool) {
        self.url = url
        self.httpStatus = httpStatus
        self.durationMs = durationMs
        self.bodyBytes = bodyBytes
        self.trace = trace
        self.viaTunnel = viaTunnel
    }

    public var isHTTPOK: Bool { (200..<300).contains(httpStatus) }

    /// Валидное доказательство: HTTP 2xx И запрос шёл через туннель.
    public var isEvidenceValid: Bool { isHTTPOK && viaTunnel }

    /// colo из trace (upper-case), если удалось определить.
    public var colo: String? { trace?.colo }
}

public enum HTTPSProbeOutcome: Sendable, Equatable {
    /// Запрос выполнен (в туннеле или нет — см. `viaTunnel`); HTTP-код любой.
    case completed(WarpHTTPSProbe)
    /// Запрос не дошёл/оборвался.
    case failed(String)
    case timedOut
    /// Движок не умеет HTTPS-пробу в этом контексте (например, extension).
    case unsupported(String)
    case cancelled

    public var probe: WarpHTTPSProbe? {
        if case .completed(let probe) = self { return probe }
        return nil
    }

    public var unsupportedReason: String? {
        if case .unsupported(let reason) = self { return reason }
        return nil
    }

    public var isCancelled: Bool {
        if case .cancelled = self { return true }
        return false
    }
}

// MARK: - UAPI-выгрузка ядра

/// Разбор `wgGetConfig()` / `getRuntimeConfiguration()` (UAPI).
///
/// Формат — строка `key=value` с секциями: сначала интерфейс
/// (`private_key`, `listen_port`), затем пиры, каждый с `public_key`
/// (`endpoint`, `last_handshake_time_sec`, `last_handshake_time_nsec`,
/// `rx_bytes`, `tx_bytes`, `persistent_keepalive_interval`).
public struct WarpRuntimeConfiguration: Sendable, Equatable {
    public struct Peer: Sendable, Equatable {
        public let publicKey: String
        public let endpoint: String?
        /// Сырое значение `last_handshake_time_sec` из UAPI ядра.
        /// Это монотонное время с момента запуска ядра, А НЕ unix-время.
        public let lastHandshakeTimeSec: UInt64
        public let rxBytes: UInt64
        public let txBytes: UInt64
        public let persistentKeepalive: String?

        public init(publicKey: String,
                    endpoint: String?,
                    lastHandshakeTimeSec: UInt64,
                    rxBytes: UInt64,
                    txBytes: UInt64,
                    persistentKeepalive: String?) {
            self.publicKey = publicKey
            self.endpoint = endpoint
            self.lastHandshakeTimeSec = lastHandshakeTimeSec
            self.rxBytes = rxBytes
            self.txBytes = txBytes
            self.persistentKeepalive = persistentKeepalive
        }

        public var hasHandshake: Bool { lastHandshakeTimeSec > 0 }

        public var endpointTarget: CandidateTarget? {
            endpoint.flatMap { CandidateTarget(endpoint: $0) }
        }
    }

    public let privateKey: String?
    public let listenPort: UInt16?
    public let peers: [Peer]

    public init(privateKey: String?, listenPort: UInt16?, peers: [Peer]) {
        self.privateKey = privateKey
        self.listenPort = listenPort
        self.peers = peers
    }

    /// Возвращает `nil`, только если строку нельзя распознать как UAPI
    /// (нет ни одного `=` в непустых строках). Валидный, но пустой конфиг
    /// возвращает значение с пустым `peers`.
    public init?(uapi: String) {
        var privateKey: String?
        var listenPort: UInt16?
        var peers: [Peer] = []
        var current: [String: String] = [:]
        var sawAssignment = false

        func flushPeer() {
            guard let publicKey = current["public_key"], !publicKey.isEmpty else {
                current.removeAll()
                return
            }
            let seconds = current["last_handshake_time_sec"].flatMap { UInt64($0) } ?? 0
            let peer = Peer(
                publicKey: publicKey,
                endpoint: current["endpoint"],
                lastHandshakeTimeSec: seconds,
                rxBytes: current["rx_bytes"].flatMap { UInt64($0) } ?? 0,
                txBytes: current["tx_bytes"].flatMap { UInt64($0) } ?? 0,
                persistentKeepalive: current["persistent_keepalive_interval"]
            )
            peers.append(peer)
            current.removeAll()
        }

        for rawLine in uapi.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }
            guard let separator = line.firstIndex(of: "=") else { continue }
            sawAssignment = true
            let key = String(line[line.startIndex..<separator])
            let value = String(line[line.index(after: separator)...])

            switch key {
            case "private_key":
                privateKey = value.isEmpty ? nil : value
            case "listen_port":
                listenPort = UInt16(value)
            case "public_key":
                // Начало очередного пира.
                flushPeer()
                current[key] = value
            case "error", "errno":
                // UAPI может добавить диагностику — не считаем это пиром.
                continue
            default:
                if !current.isEmpty {
                    current[key] = value
                } else if key == "fwmark" {
                    // Поле интерфейса, для проверки не нужно.
                    continue
                }
            }
        }
        flushPeer()

        guard sawAssignment else { return nil }
        self.privateKey = privateKey
        self.listenPort = listenPort
        self.peers = peers
    }

    /// Есть ли у хотя бы одного пира подтверждённый handshake.
    /// Для свежеподнятого ядра (каждый кандидат стартует с нуля) ненулевой
    /// `last_handshake_time_sec` может относиться только к текущей сессии.
    public var hasConfirmedHandshake: Bool {
        peers.contains { $0.hasHandshake }
    }

    /// Максимум монотонных секунд handshake среди пиров.
    public var latestHandshakeTimeSec: UInt64? {
        let values = peers.filter { $0.hasHandshake }.map { $0.lastHandshakeTimeSec }
        return values.max()
    }

    public var totalRxBytes: UInt64 {
        peers.reduce(0) { $0 &+ $1.rxBytes }
    }

    public var totalTxBytes: UInt64 {
        peers.reduce(0) { $0 &+ $1.txBytes }
    }

    public var primaryPeer: Peer? { peers.first }

    /// Подтверждённый handshake текущего сеанса ядра. `cutoff` сохранён только
    /// для совместимости сигнатуры: сравнение с unix-временем здесь невозможно,
    /// потому что ядро отдаёт монотонные секунды с момента своего запуска.
    public func freshHandshake(notBefore cutoff: Date? = nil) -> Peer? {
        peers.first { $0.hasHandshake }
    }
}

// MARK: - Протоколы движка

/// Движок, поднимающий userspace-ядро AmneziaWG/WARP.
///
/// Жизненный цикл: `start` → (`performHandshake`, `probeRTT`, `probeHTTPS`,
/// `snapshotStats`)* → `stop`. Движок обязан освободить ресурсы и восстановить
/// продовый конфиг в `stop`, даже если вызывающий код получил ошибку.
public protocol WarpEngine: AnyObject {
    var backend: WarpEngineBackend { get }

    /// Поднимает ядро на заданном endpoint. `restoreProductionOnStop == true`
    /// означает: перед стартом сохранить текущую конфигурацию и вернуть её
    /// в `stop()` (для тестового прогона внутри активного туннеля).
    func start(configuration: WarpConfig,
               target: CandidateTarget,
               restoreProductionOnStop: Bool) async throws

    func stop() async

    /// Ждёт реальный handshake (по данным ядра) не дольше `timeout`.
    func performHandshake(timeout: TimeInterval) async throws -> HandshakeOutcome

    /// Серия RTT-проб внутри туннеля (UDP/TCP, без ICMP).
    func probeRTT(_ plan: RTTProbePlan) async -> RTTProbeOutcome

    /// HTTPS-проба через туннель.
    func probeHTTPS(_ plan: HTTPSProbePlan) async -> HTTPSProbeOutcome

    /// Снимок счётчиков ядра (без побочных эффектов).
    func snapshotStats() async -> WarpEngineStats?
}

/// Фабрика движков. `availability` возвращается без асинхронности, чтобы UI
/// мог честно показать «ядро недоступно» ещё до попытки запуска.
public protocol WarpEngineFactory {
    var availability: WarpEngineAvailability { get }
    func makeEngine() throws -> any WarpEngine
}

// MARK: - Контракт тестового туннеля (уровень приложения)

/// Возможности тестового драйвера. Флаги не декоративные: валидатор по ним
/// решает, можно ли вообще присудить кандидату bucket (HTTPS/colo).
public struct TunnelTestCapabilities: Sendable, Equatable {
    public let backendIdentifier: String
    public let inTunnelRTT: Bool
    public let inTunnelHTTPS: Bool
    /// iOS не даёт два одновременных NE-туннеля: проверка обязана быть
    /// последовательной, с восстановлением продового конфига.
    public let requiresExclusiveTunnel: Bool

    public init(backendIdentifier: String,
                inTunnelRTT: Bool,
                inTunnelHTTPS: Bool,
                requiresExclusiveTunnel: Bool = true) {
        self.backendIdentifier = backendIdentifier
        self.inTunnelRTT = inTunnelRTT
        self.inTunnelHTTPS = inTunnelHTTPS
        self.requiresExclusiveTunnel = requiresExclusiveTunnel
    }

    public init(backend: WarpEngineBackend, requiresExclusiveTunnel: Bool = true) {
        self.init(backendIdentifier: backend.identifier,
                  inTunnelRTT: backend.inTunnelRTT,
                  inTunnelHTTPS: backend.inTunnelHTTPS,
                  requiresExclusiveTunnel: requiresExclusiveTunnel)
    }
}

/// Доступность тестового драйвера.
public enum TunnelTestDriverAvailability: Sendable, Equatable {
    case available(TunnelTestCapabilities)
    case unavailable(String)

    public var capabilities: TunnelTestCapabilities? {
        if case .available(let capabilities) = self { return capabilities }
        return nil
    }

    public var isAvailable: Bool { capabilities != nil }

    public var unavailableReason: String? {
        if case .unavailable(let reason) = self { return reason }
        return nil
    }
}

/// Запрос на поднятие одноразового тестового туннеля для одного кандидата.
public struct TestTunnelRequest: Sendable {
    public let configuration: WarpConfig
    public let target: CandidateTarget
    public let handshakeTimeout: TimeInterval
    public let rttPlan: RTTProbePlan
    public let httpsPlan: HTTPSProbePlan
    /// Восстановить продовый конфиг после проверки кандидата.
    public let restoreProductionTunnel: Bool

    public init(configuration: WarpConfig,
                target: CandidateTarget,
                handshakeTimeout: TimeInterval,
                rttPlan: RTTProbePlan,
                httpsPlan: HTTPSProbePlan,
                restoreProductionTunnel: Bool = true) {
        self.configuration = configuration
        self.target = target
        self.handshakeTimeout = handshakeTimeout
        self.rttPlan = rttPlan
        self.httpsPlan = httpsPlan
        self.restoreProductionTunnel = restoreProductionTunnel
    }

    /// Конфигурация WARP с подставленным endpoint кандидата.
    /// Драйверу, работающему через `WarpConfig.wgQuickData()`/`withEndpoint`,
    /// нужен именно этот вариант, а не базовый конфиг.
    public var resolvedConfiguration: WarpConfig {
        configuration.withEndpoint(host: target.host, port: target.port)
    }
}

/// Одна сессия проверки кандидата: туннель уже поднят (или поднимается
/// внутри `startTestSession`), `stop()` обязан погасить его и восстановить
/// продовое состояние.
public protocol TunnelTestSession: AnyObject {
    var target: CandidateTarget { get }
    var backend: WarpEngineBackend { get }

    func waitForHandshake(timeout: TimeInterval) async throws -> HandshakeOutcome
    func probeRTT(_ plan: RTTProbePlan) async -> RTTProbeOutcome
    func probeHTTPS(_ plan: HTTPSProbePlan) async -> HTTPSProbeOutcome
    func snapshotStats() async -> WarpEngineStats?
    func stop() async
}

/// Драйвер, который умеет последовательно поднимать/гасить тестовый туннель.
///
/// Реализуется на уровне app (`App/`): app может временно поднять NE-туннель
/// с default route, дождаться handshake через provider-сообщения, выполнить
/// URLSession-запрос к `https://www.cloudflare.com/cdn-cgi/trace` (трафик app
/// идёт через его же туннель) и погасить туннель. Внутри extension такой
/// драйвер тоже возможен, но без in-tunnel HTTPS/RTT (см. адаптер).
public protocol TunnelTestDriving {
    var availability: TunnelTestDriverAvailability { get }
    func startTestSession(_ request: TestTunnelRequest) async throws -> any TunnelTestSession
}

// MARK: - Мост: WarpEngine → TunnelTestDriving

/// Универсальный драйвер поверх `WarpEngineFactory`.
///
/// Полезен, когда тестовым туннелем управляет сам extension (последовательное
/// переключение ядра). Для app-side HTTPS-пробы через туннель нужен отдельный
/// драйвер, потому что extension-ядро не может само себе сгенерировать трафик
/// «внутрь» туннеля.
public final class WarpEngineTestDriver: TunnelTestDriving {
    private let factory: any WarpEngineFactory

    public init(factory: any WarpEngineFactory) {
        self.factory = factory
    }

    public var availability: TunnelTestDriverAvailability {
        switch factory.availability {
        case .available(let backend):
            return .available(TunnelTestCapabilities(backend: backend))
        case .unavailable(let reason):
            return .unavailable(reason)
        }
    }

    public func startTestSession(_ request: TestTunnelRequest) async throws -> any TunnelTestSession {
        guard case .available(let backend) = factory.availability else {
            throw WarpEngineError.engineUnavailable(factory.availability.unavailableReason ?? "причина не указана")
        }
        let engine = try factory.makeEngine()
        do {
            try await engine.start(configuration: request.configuration,
                                   target: request.target,
                                   restoreProductionOnStop: request.restoreProductionTunnel)
        } catch {
            // Не оставляем полуподнятое ядро: stop идемпотентен по контракту.
            await engine.stop()
            throw error
        }
        return WarpEngineTestSession(target: request.target, backend: backend, engine: engine)
    }
}

/// Сессия проверки поверх готового `WarpEngine`.
public final class WarpEngineTestSession: TunnelTestSession {
    public let target: CandidateTarget
    public let backend: WarpEngineBackend

    private let engine: any WarpEngine
    private let lock = NSLock()
    private var stopped = false

    init(target: CandidateTarget, backend: WarpEngineBackend, engine: any WarpEngine) {
        self.target = target
        self.backend = backend
        self.engine = engine
    }

    public func waitForHandshake(timeout: TimeInterval) async throws -> HandshakeOutcome {
        try await engine.performHandshake(timeout: timeout)
    }

    public func probeRTT(_ plan: RTTProbePlan) async -> RTTProbeOutcome {
        await engine.probeRTT(plan)
    }

    public func probeHTTPS(_ plan: HTTPSProbePlan) async -> HTTPSProbeOutcome {
        await engine.probeHTTPS(plan)
    }

    public func snapshotStats() async -> WarpEngineStats? {
        await engine.snapshotStats()
    }

    public func stop() async {
        lock.lock()
        let alreadyStopped = stopped
        stopped = true
        lock.unlock()
        guard !alreadyStopped else { return }
        await engine.stop()
    }

    deinit {
        // Если сессию потеряли без stop(), хотя бы попытаемся освободить ядро.
        // Вызывающий код всё равно обязан вызывать stop() явно.
        if !stopped {
            Task.detached { [engine] in await engine.stop() }
        }
    }
}

// MARK: - Утилиты

/// Монотонная шкала времени (не зависит от перевода системных часов).
public enum WarpMonotonicClock {
    public static func now() -> Double {
        Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000
    }

    public static func millisecondsSince(_ start: Double) -> Double {
        max(0, (now() - start) * 1000)
    }
}

extension Array where Element == Double {
    /// Медиана; для чётного количества — среднее двух центральных значений.
    var warpMedian: Double? {
        guard !isEmpty else { return nil }
        let sorted = self.sorted()
        let middle = sorted.count / 2
        if sorted.count % 2 == 0 {
            return (sorted[middle - 1] + sorted[middle]) / 2
        }
        return sorted[middle]
    }
}
