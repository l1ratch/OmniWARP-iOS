import Foundation
import Network

/// Разведка сетей Cloudflare через настоящие HTTP-запросы.
///
/// `/cdn-cgi/trace` — HTTP API. Scout выполняет GET `http://IP/cdn-cgi/trace`
/// с заголовком `Host: trace.cloudflare.com`, а НЕ отправляет этот запрос по UDP.
/// RTT и потери здесь описывают только HTTP-доступность IP. Порты нужны последующему
/// AWG handshake; ни HTTP 200, ни colo не доказывают доступность UDP/WireGuard.
/// UDP handshake на выбранном порту обязан проверять отдельный CandidateValidator.
public struct EndpointScout: Sendable {
    public struct Configuration: Sendable {
        public var randomHostsPerSubnet: Int
        public var ports: [UInt16]
        public var probesPerHost: Int
        public var maxConcurrentProbes: Int
        public var requestTimeout: TimeInterval
        public var excludedColos: Set<String>

        public init(
            randomHostsPerSubnet: Int = 10,
            ports: [UInt16] = [2408, 500, 4500, 987],
            probesPerHost: Int = 2,
            maxConcurrentProbes: Int = 12,
            requestTimeout: TimeInterval = 4,
            excludedColos: Set<String> = []
        ) {
            self.randomHostsPerSubnet = max(0, randomHostsPerSubnet)
            self.ports = ports.filter { $0 > 0 }.reduce(into: [UInt16]()) { unique, port in
                if !unique.contains(port) { unique.append(port) }
            }
            self.probesPerHost = max(1, probesPerHost)
            self.maxConcurrentProbes = max(1, maxConcurrentProbes)
            self.requestTimeout = max(0.1, requestTimeout)
            self.excludedColos = Set(excludedColos.map { $0.uppercased() })
        }

        public static let standard = Configuration()
    }

    public enum Event: Sendable {
        case progress(Progress)
        case finished([EndpointCandidate])
    }

    public struct Progress: Sendable {
        public var completedHosts: Int
        public var totalHosts: Int
        public var usableCandidateCount: Int
        public var latestCandidates: [EndpointCandidate]

        public var fraction: Double {
            guard totalHosts > 0 else { return 1 }
            return Double(completedHosts) / Double(totalHosts)
        }
    }

    public static let subnets = [
        "188.114.96", "188.114.97", "188.114.98", "188.114.99",
        "162.159.192", "162.159.193", "162.159.195",
        "8.34.146", "8.39.214", "8.39.204", "8.39.125",
        "8.6.112", "8.35.211", "8.47.69"
    ]

    /// Явно неизмеренный fallback. Он не содержит выдуманных RTT, loss или HTTP status.
    /// Используется готовый IPv4: extension не обязан уметь DNS-резолв hostname
    /// до того, как туннель начал передавать пакеты. `engage.cloudflareclient.com`
    /// сейчас указывает на этот anycast-адрес.
    public static let fallbackCandidate = EndpointCandidate(
        ip: "162.159.192.1",
        port: 4500,
        source: .fallback
    )

    public let configuration: Configuration
    private let session: URLSession

    public init(configuration: Configuration = .standard, session: URLSession? = nil) {
        self.configuration = configuration
        if let session {
            self.session = session
        } else {
            let sessionConfiguration = URLSessionConfiguration.ephemeral
            sessionConfiguration.timeoutIntervalForRequest = configuration.requestTimeout
            sessionConfiguration.timeoutIntervalForResource = configuration.requestTimeout * 2
            sessionConfiguration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            sessionConfiguration.urlCache = nil
            sessionConfiguration.httpCookieStorage = nil
            sessionConfiguration.httpShouldSetCookies = false
            sessionConfiguration.connectionProxyDictionary = nil
            self.session = URLSession(configuration: sessionConfiguration)
        }
    }

    /// Запускает bounded-concurrency сканирование. Колбэк вызывается после каждого IP.
    /// Отмена родительской Task отменяет ожидающие URLSession-запросы и пробрасывает
    /// CancellationError. Если ничего не прошло фильтры, возвращается только fallback.
    public func scout(
        onProgress: (@Sendable (Progress) -> Void)? = nil
    ) async throws -> [EndpointCandidate] {
        try Task.checkCancellation()
        let targets = Self.makeProbeTargets(randomHostsPerSubnet: configuration.randomHostsPerSubnet)
        guard !targets.isEmpty, !configuration.ports.isEmpty else { return [Self.fallbackCandidate] }

        return try await withThrowingTaskGroup(of: ProbeOutput.self) { group in
            var nextTargetIndex = 0
            let initialCount = min(configuration.maxConcurrentProbes, targets.count)

            for _ in 0..<initialCount {
                let target = targets[nextTargetIndex]
                nextTargetIndex += 1
                group.addTask {
                    try Task.checkCancellation()
                    return ProbeOutput(target: target, result: try await self.probe(ip: target.ip))
                }
            }

            var completed = 0
            var candidates: [EndpointCandidate] = []
            while true {
                guard let output = try await group.next() else { break }
                try Task.checkCancellation()
                completed += 1
                let latest = self.candidates(for: output.result, source: output.target.source)
                candidates.append(contentsOf: latest)
                onProgress?(Progress(
                    completedHosts: completed,
                    totalHosts: targets.count,
                    usableCandidateCount: candidates.count,
                    latestCandidates: latest
                ))

                if nextTargetIndex < targets.count {
                    let target = targets[nextTargetIndex]
                    nextTargetIndex += 1
                    group.addTask {
                        try Task.checkCancellation()
                        return ProbeOutput(target: target, result: try await self.probe(ip: target.ip))
                    }
                }
            }

            try Task.checkCancellation()
            let sorted = candidates.sorted {
                let leftRTT = $0.rttMilliseconds ?? .infinity
                let rightRTT = $1.rttMilliseconds ?? .infinity
                if leftRTT != rightRTT { return leftRTT < rightRTT }
                if $0.ip != $1.ip { return $0.ip < $1.ip }
                return $0.port < $1.port
            }
            return sorted.isEmpty ? [Self.fallbackCandidate] : sorted
        }
    }

    /// Формирует набор для реального AWG handshake, а не просто fastest-HTTP top-N.
    /// Порт 4500 обязан попасть в проверку: это основной WARP-порт и во многих
    /// сетях единственный рабочий. Затем добавляются альтернативные порты и IP.
    public static func validationCandidates(
        from candidates: [EndpointCandidate],
        limit: Int = 3
    ) -> [EndpointCandidate] {
        guard limit > 0 else { return [] }
        var selected: [EndpointCandidate] = []
        var identifiers = Set<String>()

        func append(_ candidate: EndpointCandidate) {
            guard selected.count < limit, identifiers.insert(candidate.id).inserted else { return }
            selected.append(candidate)
        }

        for port in [4500, 2408, 500, 987] {
            guard selected.count < limit else { break }
            let bestForPort = candidates
                .filter { $0.port == port }
                .min { ($0.rttMilliseconds ?? .infinity) < ($1.rttMilliseconds ?? .infinity) }
            if let bestForPort { append(bestForPort) }
        }

        // Если остались места, добавляем endpoint'ы на других IP, чтобы не
        // проверять всё на одной проблемной подсети.
        for candidate in candidates where selected.count < limit {
            if selected.contains(where: { $0.ip == candidate.ip }) { continue }
            append(candidate)
        }
        // Портовое разнообразие важнее, но при малом наборе добираем любые.
        for candidate in candidates where selected.count < limit {
            append(candidate)
        }
        return selected.isEmpty && !candidates.isEmpty ? [fallbackCandidate] : selected
    }

    /// AsyncStream-вариант API. Отмена потребления stream отменяет всю операцию.
    public func scoutEvents() -> AsyncThrowingStream<Event, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let result = try await scout { progress in
                        continuation.yield(.progress(progress))
                    }
                    continuation.yield(.finished(result))
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    /// Выполняет настоящие trace-запросы к одному IPv4 и агрегирует их результат.
    /// Пытается HTTPS (порт 443) первым: на сотовых сетях РФ plain HTTP к
    /// произвольным IP часто перехватывается DPI. HTTP — запасной вариант.
    /// Метод не отбрасывает запрещённые colo — фильтрация происходит в `scout`.
    public func probe(ip: String) async throws -> TraceResult {
        guard IPv4Address(ip) != nil else { throw EndpointScoutError.invalidIPv4 }

        var successfulRTTs: [Double] = []
        var lastColo: String?
        var lastStatus: Int?
        var successfulStatus: Int?
        var warpEnabled: Bool?

        for _ in 0..<configuration.probesPerHost {
            try Task.checkCancellation()

            // HTTPS первичен: DPI на сотовых сетях режет plain HTTP
            // к IP, не входящим в белый список. HTTPS-пакет к Cloudflare
            // TTL-маскировкой обойти сложнее, но trace на том же IP работает.
            let schemes = ["https", "http"]
            for scheme in schemes {
                guard let url = URL(string: "\(scheme)://\(ip)/cdn-cgi/trace") else {
                    throw EndpointScoutError.invalidIPv4
                }
                var request = URLRequest(
                    url: url,
                    cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
                    timeoutInterval: configuration.requestTimeout
                )
                request.httpMethod = "GET"
                request.setValue("trace.cloudflare.com", forHTTPHeaderField: "Host")
                request.setValue("close", forHTTPHeaderField: "Connection")
                request.setValue("OmniWARP/1.0", forHTTPHeaderField: "User-Agent")

                let clock = ContinuousClock()
                let started = clock.now
                do {
                    let (data, response) = try await session.data(for: request)
                    let duration = started.duration(to: clock.now)
                    let rtt = Double(duration.components.seconds) * 1000
                        + Double(duration.components.attoseconds) / 1_000_000_000_000_000
                    let status = (response as? HTTPURLResponse)?.statusCode
                    lastStatus = status

                    let fields = Self.parseTrace(data)
                    let colo = fields["colo"]?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
                    if let status, (200..<300).contains(status), let colo, !colo.isEmpty {
                        successfulRTTs.append(rtt)
                        lastColo = colo
                        successfulStatus = status
                        if let warp = fields["warp"] { warpEnabled = warp.lowercased() == "on" }
                        break // HTTPS или HTTP сработал — идём к следующей пробе
                    }
                } catch {
                    if Task.isCancelled || (error as? URLError)?.code == .cancelled {
                        throw CancellationError()
                    }
                    // Пробуем следующий scheme (HTTP после HTTPS).
                }
            }
        }

        let attempts = configuration.probesPerHost
        let failed = attempts - successfulRTTs.count
        let averageRTT = successfulRTTs.isEmpty
            ? nil
            : successfulRTTs.reduce(0, +) / Double(successfulRTTs.count)
        return TraceResult(
            ip: ip,
            colo: lastColo,
            rttMilliseconds: averageRTT,
            lossPercentage: Double(failed) / Double(attempts) * 100,
            httpsStatus: successfulStatus ?? lastStatus,
            warpEnabled: warpEnabled
        )
    }

    private func candidates(for trace: TraceResult, source: EndpointSource) -> [EndpointCandidate] {
        guard let colo = trace.colo,
              !colo.isEmpty,
              !configuration.excludedColos.contains(colo.uppercased()),
              let rtt = trace.rttMilliseconds,
              let status = trace.httpsStatus,
              (200..<300).contains(status) else { return [] }

        // Trace измеряет IP один раз; порт добавляется только как цель будущего handshake.
        return configuration.ports.map { port in
            EndpointCandidate(
                ip: trace.ip,
                port: port,
                colo: colo,
                rttMilliseconds: rtt,
                lossPercentage: trace.lossPercentage,
                httpsStatus: status,
                source: source
            )
        }
    }

    private static func parseTrace(_ data: Data) -> [String: String] {
        guard !data.isEmpty, data.count <= 1_048_576,
              let text = String(data: data, encoding: .utf8) else { return [:] }
        var fields: [String: String] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            guard let separator = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<separator])
            let value = String(line[line.index(after: separator)...])
            if !key.isEmpty { fields[key] = value }
        }
        return fields
    }

    private static func makeProbeTargets(randomHostsPerSubnet: Int) -> [ProbeTarget] {
        var targets: [ProbeTarget] = []
        targets.reserveCapacity(subnets.count * (randomHostsPerSubnet + 1))
        for subnet in subnets {
            targets.append(ProbeTarget(ip: "\(subnet).1", source: .anchor))
            var randomOctets = Set<UInt32>()
            while randomOctets.count < randomHostsPerSubnet {
                randomOctets.insert(UInt32.random(in: 2...254))
            }
            for octet in randomOctets {
                targets.append(ProbeTarget(ip: "\(subnet).\(octet)", source: .random))
            }
        }
        return targets
    }

    private struct ProbeTarget: Sendable {
        var ip: String
        var source: EndpointSource
    }

    private struct ProbeOutput: Sendable {
        var target: ProbeTarget
        var result: TraceResult
    }
}

public enum EndpointScoutError: LocalizedError, Sendable {
    case invalidIPv4

    public var errorDescription: String? {
        switch self {
        case .invalidIPv4: return "EndpointScout принимает только корректный IPv4-адрес."
        }
    }
}
