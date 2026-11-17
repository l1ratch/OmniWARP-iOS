import Foundation
import Dispatch
import Network

public enum DNSCodecError: Error, Equatable, Sendable {
    case truncated
    case invalidFlags
    case invalidLabelLength
    case invalidNamePointer
    case namePointerLoop
    case nameTooLong
    case invalidUTF8Label
    case invalidRecordLength
    case tooManyRecords
    case invalidAddressLength
}

public enum DNSRecordType: UInt16, Sendable {
    case a = 1
    case cname = 5
    case aaaa = 28
    case any = 255
}

public struct DNSHeader: Equatable, Sendable {
    public let id: UInt16
    public let isResponse: Bool
    public let opcode: UInt8
    public let authoritativeAnswer: Bool
    public let truncated: Bool
    public let recursionDesired: Bool
    public let recursionAvailable: Bool
    public let authenticatedData: Bool
    public let checkingDisabled: Bool
    public let responseCode: UInt8

    public init(
        id: UInt16,
        isResponse: Bool = false,
        opcode: UInt8 = 0,
        authoritativeAnswer: Bool = false,
        truncated: Bool = false,
        recursionDesired: Bool = true,
        recursionAvailable: Bool = false,
        authenticatedData: Bool = false,
        checkingDisabled: Bool = false,
        responseCode: UInt8 = 0
    ) {
        self.id = id
        self.isResponse = isResponse
        self.opcode = opcode
        self.authoritativeAnswer = authoritativeAnswer
        self.truncated = truncated
        self.recursionDesired = recursionDesired
        self.recursionAvailable = recursionAvailable
        self.authenticatedData = authenticatedData
        self.checkingDisabled = checkingDisabled
        self.responseCode = responseCode
    }

    public init(id: UInt16, flags: UInt16) {
        self.init(
            id: id,
            isResponse: flags & 0x8000 != 0,
            opcode: UInt8((flags >> 11) & 0x0f),
            authoritativeAnswer: flags & 0x0400 != 0,
            truncated: flags & 0x0200 != 0,
            recursionDesired: flags & 0x0100 != 0,
            recursionAvailable: flags & 0x0080 != 0,
            authenticatedData: flags & 0x0020 != 0,
            checkingDisabled: flags & 0x0010 != 0,
            responseCode: UInt8(flags & 0x000f)
        )
    }

    public var flags: UInt16 {
        var value: UInt16 = 0
        if isResponse { value |= 0x8000 }
        value |= UInt16(opcode & 0x0f) << 11
        if authoritativeAnswer { value |= 0x0400 }
        if truncated { value |= 0x0200 }
        if recursionDesired { value |= 0x0100 }
        if recursionAvailable { value |= 0x0080 }
        if authenticatedData { value |= 0x0020 }
        if checkingDisabled { value |= 0x0010 }
        value |= UInt16(responseCode & 0x0f)
        return value
    }
}

public struct DNSQuestion: Equatable, Sendable {
    public let name: String
    public let type: UInt16
    public let queryClass: UInt16

    public init(name: String, type: UInt16, queryClass: UInt16 = 1) {
        self.name = name
        self.type = type
        self.queryClass = queryClass
    }
}

public struct DNSResourceRecord: Equatable, Sendable {
    public let name: String
    public let type: UInt16
    public let recordClass: UInt16
    public let timeToLive: UInt32
    public let data: Data

    public init(name: String, type: UInt16, recordClass: UInt16 = 1, timeToLive: UInt32, data: Data) {
        self.name = name
        self.type = type
        self.recordClass = recordClass
        self.timeToLive = timeToLive
        self.data = data
    }

    public static func a(name: String, address: String, timeToLive: UInt32) throws -> DNSResourceRecord {
        let parts = address.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { throw DNSCodecError.invalidAddressLength }
        var bytes = Data()
        for part in parts {
            guard let byte = UInt8(String(part)) else { throw DNSCodecError.invalidAddressLength }
            bytes.append(byte)
        }
        return DNSResourceRecord(name: name, type: DNSRecordType.a.rawValue, timeToLive: timeToLive, data: bytes)
    }
}

/// RFC 1035 message with uncompressed, deterministic serialization. The parser
/// accepts compression pointers in every owner-name position and rejects loops.
public struct DNSMessage: Equatable, Sendable {
    public let header: DNSHeader
    public let questions: [DNSQuestion]
    public let answers: [DNSResourceRecord]
    public let authorities: [DNSResourceRecord]
    public let additionals: [DNSResourceRecord]

    public init(
        header: DNSHeader,
        questions: [DNSQuestion] = [],
        answers: [DNSResourceRecord] = [],
        authorities: [DNSResourceRecord] = [],
        additionals: [DNSResourceRecord] = []
    ) {
        self.header = header
        self.questions = questions
        self.answers = answers
        self.authorities = authorities
        self.additionals = additionals
    }

    public init(data: Data) throws {
        self = try Self.parse(data)
    }

    public static func parse(_ data: Data) throws -> DNSMessage {
        var parser = Parser(bytes: Array(data))
        let id = try parser.readUInt16()
        let flags = try parser.readUInt16()
        let header = DNSHeader(id: id, flags: flags)
        let questionCount = Int(try parser.readUInt16())
        let answerCount = Int(try parser.readUInt16())
        let authorityCount = Int(try parser.readUInt16())
        let additionalCount = Int(try parser.readUInt16())

        var questions: [DNSQuestion] = []
        questions.reserveCapacity(questionCount)
        for _ in 0..<questionCount {
            questions.append(DNSQuestion(
                name: try parser.readName(),
                type: try parser.readUInt16(),
                queryClass: try parser.readUInt16()
            ))
        }

        let answers = try parser.readRecords(answerCount)
        let authorities = try parser.readRecords(authorityCount)
        let additionals = try parser.readRecords(additionalCount)
        return DNSMessage(
            header: header,
            questions: questions,
            answers: answers,
            authorities: authorities,
            additionals: additionals
        )
    }

    public func serialized() throws -> Data {
        guard questions.count <= Int(UInt16.max), answers.count <= Int(UInt16.max),
              authorities.count <= Int(UInt16.max), additionals.count <= Int(UInt16.max) else {
            throw DNSCodecError.tooManyRecords
        }

        var writer = Writer()
        writer.appendUInt16(header.id)
        writer.appendUInt16(header.flags)
        writer.appendUInt16(UInt16(questions.count))
        writer.appendUInt16(UInt16(answers.count))
        writer.appendUInt16(UInt16(authorities.count))
        writer.appendUInt16(UInt16(additionals.count))

        for question in questions {
            try writer.appendName(question.name)
            writer.appendUInt16(question.type)
            writer.appendUInt16(question.queryClass)
        }
        for record in [answers, authorities, additionals].joined() {
            try writer.appendName(record.name)
            writer.appendUInt16(record.type)
            writer.appendUInt16(record.recordClass)
            writer.appendUInt32(record.timeToLive)
            guard record.data.count <= Int(UInt16.max) else {
                throw DNSCodecError.invalidRecordLength
            }
            writer.appendUInt16(UInt16(record.data.count))
            writer.appendData(record.data)
        }
        return writer.data
    }

    public func encode() throws -> Data {
        try serialized()
    }

    public static func standardQuery(id: UInt16, domain: String, type: UInt16) throws -> Data {
        try DNSMessage(
            header: DNSHeader(id: id),
            questions: [DNSQuestion(name: domain, type: type)]
        ).serialized()
    }

    public static func noErrorEmptyResponse(to query: DNSMessage) -> DNSMessage {
        DNSMessage(
            header: DNSHeader(
                id: query.header.id,
                isResponse: true,
                opcode: query.header.opcode,
                recursionDesired: query.header.recursionDesired,
                recursionAvailable: true,
                checkingDisabled: query.header.checkingDisabled
            ),
            questions: query.questions
        )
    }

    public func realAddresses(domain: String, family: IPAddressFamily? = nil) -> [ResolvedAddress] {
        guard header.responseCode == 0 else { return [] }
        return answers.compactMap { record in
            guard record.recordClass == 1 else { return nil }
            let recordFamily: IPAddressFamily
            switch record.type {
            case 1 where record.data.count == 4:
                recordFamily = .ipv4
            case 28 where record.data.count == 16:
                recordFamily = .ipv6
            default:
                return nil
            }
            if let family, family != recordFamily { return nil }
            let address = recordFamily == .ipv4
                ? record.data.map { String($0) }.joined(separator: ".")
                : Self.formatIPv6(record.data)
            return try? ResolvedAddress(
                address: address,
                timeToLive: record.timeToLive,
                sourceDomain: domain
            )
        }
    }

    /// Longest-run zero compression yields a stable IPv6 string accepted by
    /// Network.framework without relying on platform description formatting.
    public static func formatIPv6(_ data: Data) -> String {
        guard data.count == 16 else { return "" }
        let bytes = Array(data)
        var words: [UInt16] = []
        for index in stride(from: 0, to: 16, by: 2) {
            words.append(UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1]))
        }

        var bestStart = -1
        var bestLength = 0
        var index = 0
        while index < 8 {
            if words[index] == 0 {
                let start = index
                while index < 8 && words[index] == 0 { index += 1 }
                if index - start > bestLength && index - start >= 2 {
                    bestStart = start
                    bestLength = index - start
                }
            } else {
                index += 1
            }
        }

        let hexadecimal = words.map { String($0, radix: 16) }
        if bestStart >= 0 {
            let head = hexadecimal[..<bestStart].joined(separator: ":")
            let tail = hexadecimal[(bestStart + bestLength)...].joined(separator: ":")
            return head + "::" + tail
        }
        return hexadecimal.joined(separator: ":")
    }

    private struct Writer {
        private(set) var data = Data()

        mutating func appendUInt16(_ value: UInt16) {
            data.append(UInt8(value >> 8))
            data.append(UInt8(value & 0xff))
        }

        mutating func appendUInt32(_ value: UInt32) {
            data.append(UInt8((value >> 24) & 0xff))
            data.append(UInt8((value >> 16) & 0xff))
            data.append(UInt8((value >> 8) & 0xff))
            data.append(UInt8(value & 0xff))
        }

        mutating func appendData(_ value: Data) {
            data.append(value)
        }

        mutating func appendName(_ name: String) throws {
            if name == "." || name.isEmpty {
                data.append(0)
                return
            }
            var value = name
            if value.hasSuffix(".") { value.removeLast() }
            let labels = value.split(separator: ".", omittingEmptySubsequences: false)
            var wireLength = 1
            for substring in labels {
                let label = Array(substring.utf8)
                guard !label.isEmpty, label.count <= 63 else {
                    throw DNSCodecError.invalidLabelLength
                }
                wireLength += label.count + 1
                guard wireLength <= 255 else { throw DNSCodecError.nameTooLong }
                data.append(UInt8(label.count))
                data.append(contentsOf: label)
            }
            data.append(0)
        }
    }

    private struct Parser {
        let bytes: [UInt8]
        var offset = 0

        mutating func readUInt16() throws -> UInt16 {
            guard offset + 2 <= bytes.count else { throw DNSCodecError.truncated }
            let value = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
            offset += 2
            return value
        }

        mutating func readUInt32() throws -> UInt32 {
            guard offset + 4 <= bytes.count else { throw DNSCodecError.truncated }
            let value = UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 |
                UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
            offset += 4
            return value
        }

        mutating func readName() throws -> String {
            var cursor = offset
            var resumeOffset: Int?
            var labels: [String] = []
            var visited: Set<Int> = []
            var expandedLength = 1
            var jumps = 0

            while true {
                guard cursor < bytes.count else { throw DNSCodecError.truncated }
                let length = bytes[cursor]
                if length & 0xc0 == 0xc0 {
                    guard cursor + 1 < bytes.count else { throw DNSCodecError.truncated }
                    let pointer = Int(length & 0x3f) << 8 | Int(bytes[cursor + 1])
                    guard pointer < bytes.count else { throw DNSCodecError.invalidNamePointer }
                    if resumeOffset == nil { resumeOffset = cursor + 2 }
                    guard visited.insert(pointer).inserted else { throw DNSCodecError.namePointerLoop }
                    jumps += 1
                    guard jumps <= 128 else { throw DNSCodecError.namePointerLoop }
                    cursor = pointer
                    continue
                }

                guard length & 0xc0 == 0 else { throw DNSCodecError.invalidLabelLength }
                if length == 0 {
                    if resumeOffset == nil { resumeOffset = cursor + 1 }
                    break
                }
                guard length <= 63 else { throw DNSCodecError.invalidLabelLength }
                let start = cursor + 1
                let end = start + Int(length)
                guard end <= bytes.count else { throw DNSCodecError.truncated }
                expandedLength += Int(length) + 1
                guard expandedLength <= 255 else { throw DNSCodecError.nameTooLong }
                guard let label = String(bytes: bytes[start..<end], encoding: .utf8) else {
                    throw DNSCodecError.invalidUTF8Label
                }
                labels.append(label)
                cursor = end
            }

            guard let resumeOffset else { throw DNSCodecError.truncated }
            offset = resumeOffset
            return labels.isEmpty ? "." : labels.joined(separator: ".")
        }

        mutating func readRecords(_ count: Int) throws -> [DNSResourceRecord] {
            var records: [DNSResourceRecord] = []
            records.reserveCapacity(count)
            for _ in 0..<count {
                let name = try readName()
                let type = try readUInt16()
                let recordClass = try readUInt16()
                let ttl = try readUInt32()
                let length = Int(try readUInt16())
                guard length >= 0, offset + length <= bytes.count else {
                    throw DNSCodecError.invalidRecordLength
                }
                let recordData = Data(bytes[offset..<(offset + length)])
                offset += length
                records.append(DNSResourceRecord(
                    name: name,
                    type: type,
                    recordClass: recordClass,
                    timeToLive: ttl,
                    data: recordData
                ))
            }
            return records
        }
    }
}

public protocol DNSUpstreamResolver: Sendable {
    func resolve(query: Data) async throws -> Data
}

public enum DNSResolverError: Error, Equatable, Sendable {
    case invalidPort
    case timeout
    case connectionFailed(String)
    case emptyResponse
    case responseIDMismatch
}

/// One independent NWConnection per query; no mutable socket state is shared.
public struct NWUDPUpstreamResolver: DNSUpstreamResolver, Sendable {
    public let host: String
    public let port: UInt16
    public let timeout: TimeInterval

    public init(host: String = "1.1.1.1", port: UInt16 = 53, timeout: TimeInterval = 5) {
        self.host = host
        self.port = port
        self.timeout = timeout
    }

    public func resolve(query: Data) async throws -> Data {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
            throw DNSResolverError.invalidPort
        }
        guard query.count >= 2 else { throw DNSCodecError.truncated }
        let expectedID = UInt16(query[query.startIndex]) << 8 | UInt16(query[query.index(after: query.startIndex)])
        let state = UDPRequestState()

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                state.start(
                    query: query,
                    expectedID: expectedID,
                    host: .init(host),
                    port: endpointPort,
                    timeout: timeout.isFinite ? min(max(timeout, 0.05), 3_600) : 5,
                    continuation: continuation
                )
            }
        } onCancel: {
            state.cancel()
        }
    }
}

extension NWUDPUpstreamResolver: DomainAddressResolver {
    public func resolve(domain: String, family: IPAddressFamily) async throws -> [ResolvedAddress] {
        let query = try DNSMessage.standardQuery(
            id: UInt16.random(in: UInt16.min...UInt16.max),
            domain: domain,
            type: family.dnsRecordType
        )
        let response = try await resolve(query: query)
        return try DNSMessage.parse(response).realAddresses(domain: domain, family: family)
    }
}

private final class UDPRequestState: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    private var terminalResult: Result<Data, Error>?
    private var connection: NWConnection?
    private var timeoutTask: Task<Void, Never>?

    func start(
        query: Data,
        expectedID: UInt16,
        host: NWEndpoint.Host,
        port: NWEndpoint.Port,
        timeout: TimeInterval,
        continuation: CheckedContinuation<Data, Error>
    ) {
        lock.lock()
        if let terminalResult {
            lock.unlock()
            continuation.resume(with: terminalResult)
            return
        }
        self.continuation = continuation
        let connection = NWConnection(host: host, port: port, using: .udp)
        self.connection = connection
        lock.unlock()

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                connection.send(content: query, completion: .contentProcessed { error in
                    if let error {
                        self.complete(.failure(DNSResolverError.connectionFailed(String(describing: error))))
                        return
                    }
                    connection.receiveMessage { data, _, _, error in
                        if let error {
                            self.complete(.failure(DNSResolverError.connectionFailed(String(describing: error))))
                            return
                        }
                        guard let data, data.count >= 2 else {
                            self.complete(.failure(DNSResolverError.emptyResponse))
                            return
                        }
                        let id = UInt16(data[data.startIndex]) << 8 |
                            UInt16(data[data.index(after: data.startIndex)])
                        guard id == expectedID else {
                            self.complete(.failure(DNSResolverError.responseIDMismatch))
                            return
                        }
                        self.complete(.success(data))
                    }
                })
            case .failed(let error):
                self.complete(.failure(DNSResolverError.connectionFailed(String(describing: error))))
            case .cancelled:
                self.complete(.failure(CancellationError()))
            default:
                break
            }
        }

        let timeoutTask = Task { [weak self] in
            do {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                self?.complete(.failure(DNSResolverError.timeout))
            } catch {
                // Normal completion cancels the timeout.
            }
        }
        lock.lock()
        self.timeoutTask = timeoutTask
        lock.unlock()
        connection.start(queue: DispatchQueue(label: "omniwarp.dns.upstream", qos: .userInitiated))
    }

    func cancel() {
        complete(.failure(CancellationError()))
    }

    private func complete(_ result: Result<Data, Error>) {
        lock.lock()
        guard terminalResult == nil else {
            lock.unlock()
            return
        }
        terminalResult = result
        let continuation = self.continuation
        self.continuation = nil
        let connection = self.connection
        self.connection = nil
        let timeoutTask = self.timeoutTask
        self.timeoutTask = nil
        lock.unlock()

        timeoutTask?.cancel()
        connection?.cancel()
        continuation?.resume(with: result)
    }
}

public enum AAAAQueryBehavior: Sendable, Equatable {
    /// Forward AAAA upstream and install exact /128 routes from the response.
    case directUpstream
    /// Return NOERROR/NODATA without contacting upstream for routed domains.
    case noErrorEmpty
}

public struct DNSInterceptionResult: Sendable {
    public let response: Data
    public let matchedDomain: String?
    public let addresses: [ResolvedAddress]
    public let routeSnapshot: RouteSnapshot?

    public init(
        response: Data,
        matchedDomain: String?,
        addresses: [ResolvedAddress],
        routeSnapshot: RouteSnapshot?
    ) {
        self.response = response
        self.matchedDomain = matchedDomain
        self.addresses = addresses
        self.routeSnapshot = routeSnapshot
    }
}

/// Transparent DNS interceptor: responses are never replaced with FakeIP.
public actor DNSInterceptor {
    public let router: DomainRouter
    public let upstream: any DNSUpstreamResolver
    public let aaaaBehavior: AAAAQueryBehavior

    public init(
        router: DomainRouter,
        upstream: any DNSUpstreamResolver,
        aaaaBehavior: AAAAQueryBehavior = .directUpstream
    ) {
        self.router = router
        self.upstream = upstream
        self.aaaaBehavior = aaaaBehavior
    }

    public func handle(query: Data, now: Date = Date()) async throws -> DNSInterceptionResult {
        let message = try DNSMessage.parse(query)
        guard !message.header.isResponse,
              message.header.opcode == 0,
              message.questions.count == 1,
              let question = message.questions.first,
              question.queryClass == 1,
              question.type == DNSRecordType.a.rawValue || question.type == DNSRecordType.aaaa.rawValue else {
            let response = try await upstream.resolve(query: query)
            return DNSInterceptionResult(response: response, matchedDomain: nil, addresses: [], routeSnapshot: nil)
        }

        guard let domain = try? DomainList.normalize(question.name) else {
            let response = try await upstream.resolve(query: query)
            return DNSInterceptionResult(response: response, matchedDomain: nil, addresses: [], routeSnapshot: nil)
        }
        let domains = await router.sharedSnapshot
        guard domains.contains(domain) else {
            let response = try await upstream.resolve(query: query)
            return DNSInterceptionResult(response: response, matchedDomain: nil, addresses: [], routeSnapshot: nil)
        }

        if question.type == DNSRecordType.aaaa.rawValue && aaaaBehavior == .noErrorEmpty {
            let response = try DNSMessage.noErrorEmptyResponse(to: message).serialized()
            let snapshot = await router.routeSnapshot(now: now)
            return DNSInterceptionResult(response: response, matchedDomain: domain, addresses: [], routeSnapshot: snapshot)
        }

        let responseData = try await upstream.resolve(query: query)
        let response = try DNSMessage.parse(responseData)
        guard response.header.id == message.header.id else {
            throw DNSResolverError.responseIDMismatch
        }
        let family: IPAddressFamily = question.type == DNSRecordType.a.rawValue ? .ipv4 : .ipv6
        let addresses = response.realAddresses(domain: domain, family: family)
        let snapshot = try await router.recordResolution(
            domain: domain,
            addresses: addresses,
            family: family,
            now: now
        )
        return DNSInterceptionResult(
            response: responseData,
            matchedDomain: domain,
            addresses: addresses,
            routeSnapshot: snapshot
        )
    }

    public func response(for query: Data, now: Date = Date()) async throws -> Data {
        let result = try await handle(query: query, now: now)
        return result.response
    }
}

/// Minimal packetFlow inspector for unfragmented UDP/53 IPv4 and IPv6 packets.
public enum DNSPacketInspector {
    public struct UDPDatagram: Sendable, Equatable {
        public let sourcePort: UInt16
        public let destinationPort: UInt16
        public let payload: Data
    }

    public static func udpDatagram(in packet: Data) -> UDPDatagram? {
        let bytes = Array(packet)
        guard let first = bytes.first else { return nil }
        let udpOffset: Int
        switch first >> 4 {
        case 4:
            guard bytes.count >= 20 else { return nil }
            let headerLength = Int(first & 0x0f) * 4
            guard headerLength >= 20, bytes.count >= headerLength + 8,
                  bytes[9] == 17 else { return nil }
            let fragmentField = Int(bytes[6]) << 8 | Int(bytes[7])
            guard fragmentField & 0x3fff == 0 else { return nil }
            let totalLength = Int(bytes[2]) << 8 | Int(bytes[3])
            guard totalLength >= headerLength + 8, totalLength <= bytes.count else { return nil }
            udpOffset = headerLength
        case 6:
            guard bytes.count >= 48, bytes[6] == 17 else { return nil }
            let payloadLength = Int(bytes[4]) << 8 | Int(bytes[5])
            guard payloadLength >= 8, payloadLength + 40 <= bytes.count else { return nil }
            udpOffset = 40
        default:
            return nil
        }

        let sourcePort = UInt16(bytes[udpOffset]) << 8 | UInt16(bytes[udpOffset + 1])
        let destinationPort = UInt16(bytes[udpOffset + 2]) << 8 | UInt16(bytes[udpOffset + 3])
        let udpLength = Int(bytes[udpOffset + 4]) << 8 | Int(bytes[udpOffset + 5])
        guard udpLength >= 8, udpOffset + udpLength <= bytes.count else { return nil }
        return UDPDatagram(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            payload: Data(bytes[(udpOffset + 8)..<(udpOffset + udpLength)])
        )
    }

    public static func isDNSQuery(_ packet: Data) -> Bool {
        udpDatagram(in: packet)?.destinationPort == 53
    }
}

/// Isolated future-netstack component. It is deliberately not referenced by
/// DNSInterceptor, DomainRouter, or any WARP route generation code.
public actor FakeIPPool {
    public struct Mapping: Sendable, Equatable {
        public let domain: String
        public let address: String
        public let expiresAt: Date
    }

    private struct Entry: Sendable {
        let domain: String
        let addressIndex: Int
        var expiresAt: Date
        var lastUsed: UInt64
    }

    private let capacity: Int
    private let defaultTTL: TimeInterval
    private var byDomain: [String: Entry] = [:]
    private var byAddress: [Int: String] = [:]
    private var nextAddressIndex = 1
    private var clock: UInt64 = 0

    public init(capacity: Int = 254, defaultTTL: UInt32 = 300) {
        self.capacity = min(max(capacity, 1), 254)
        self.defaultTTL = TimeInterval(max(defaultTTL, 1))
    }

    public var count: Int {
        byDomain.count
    }

    @discardableResult
    public func address(for domain: String, now: Date = Date()) throws -> String {
        let normalized = try DomainList.normalize(domain)
        removeExpired(now: now)
        clock &+= 1

        if var existing = byDomain[normalized] {
            existing.expiresAt = now.addingTimeInterval(defaultTTL)
            existing.lastUsed = clock
            byDomain[normalized] = existing
            return Self.addressString(existing.addressIndex)
        }

        if byDomain.count >= capacity, let victim = byDomain.values.min(by: { $0.lastUsed < $1.lastUsed }) {
            // Remove both directions before allocating the freed address.
            byDomain.removeValue(forKey: victim.domain)
            byAddress.removeValue(forKey: victim.addressIndex)
        }

        var freeIndex: Int?
        for offset in 0..<254 {
            let candidate = ((nextAddressIndex - 1 + offset) % 254) + 1
            if byAddress[candidate] == nil {
                freeIndex = candidate
                nextAddressIndex = candidate == 254 ? 1 : candidate + 1
                break
            }
        }
        guard let index = freeIndex else {
            // Capacity is <= 254, so this indicates no live address conflict;
            // keep the error explicit rather than returning a duplicate mapping.
            throw FakeIPPoolError.exhausted
        }

        let address = Self.addressString(index)
        byDomain[normalized] = Entry(
            domain: normalized,
            addressIndex: index,
            expiresAt: now.addingTimeInterval(defaultTTL),
            lastUsed: clock
        )
        byAddress[index] = normalized
        return address
    }

    public func domain(for address: String, now: Date = Date()) -> String? {
        guard let index = Self.addressIndex(address) else { return nil }
        guard let domain = byAddress[index], let entry = byDomain[domain] else {
            byAddress.removeValue(forKey: index)
            return nil
        }
        guard entry.expiresAt > now else {
            byAddress.removeValue(forKey: index)
            byDomain.removeValue(forKey: domain)
            return nil
        }
        clock &+= 1
        byDomain[domain]?.lastUsed = clock
        return domain
    }

    public func mapping(for address: String, now: Date = Date()) -> Mapping? {
        guard let domain = domain(for: address, now: now),
              let index = Self.addressIndex(address),
              let entry = byDomain[domain] else { return nil }
        return Mapping(domain: domain, address: Self.addressString(index), expiresAt: entry.expiresAt)
    }

    public func mappings(now: Date = Date()) -> [Mapping] {
        removeExpired(now: now)
        return byDomain.values.map {
            Mapping(domain: $0.domain, address: Self.addressString($0.addressIndex), expiresAt: $0.expiresAt)
        }.sorted { $0.domain < $1.domain }
    }

    public func removeExpired(now: Date = Date()) {
        let expired = byDomain.values.filter { $0.expiresAt <= now }
        for entry in expired {
            byDomain.removeValue(forKey: entry.domain)
            byAddress.removeValue(forKey: entry.addressIndex)
        }
    }

    private static func addressString(_ index: Int) -> String {
        "198.18.4.\(index)"
    }

    private static func addressIndex(_ address: String) -> Int? {
        let parts = address.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4,
              parts[0] == "198", parts[1] == "18", parts[2] == "4",
              let index = Int(parts[3]), (1...254).contains(index) else { return nil }
        return index
    }
}

public enum FakeIPPoolError: Error, Equatable, Sendable {
    case exhausted
}
