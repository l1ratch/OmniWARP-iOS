import Foundation
import Network

public enum SNIExtractionResult: Equatable, Sendable {
    case incomplete
    case found(String)
    case notTLS
    case noSNI
    case malformed
    case limitExceeded
}

/// Incremental TLS ClientHello SNI parser. It handles arbitrary TCP chunks and
/// handshake fragmentation across TLS records without unbounded buffering.
public struct SNIExtractor: Sendable {
    public static let defaultMaximumBufferSize = 128 * 1_024
    private static let maximumHandshakeSize = 65_535

    private let maximumBufferSize: Int
    private var buffer = Data()
    private var terminalResult: SNIExtractionResult?

    public init(maximumBufferSize: Int = SNIExtractor.defaultMaximumBufferSize) {
        self.maximumBufferSize = max(maximumBufferSize, 5)
    }

    public var bufferedByteCount: Int {
        buffer.count
    }

    public mutating func append(_ chunk: Data) -> SNIExtractionResult {
        if let terminalResult { return terminalResult }
        guard buffer.count + chunk.count <= maximumBufferSize else {
            terminalResult = .limitExceeded
            buffer.removeAll(keepingCapacity: false)
            return .limitExceeded
        }
        buffer.append(chunk)
        let result = Self.parse(buffer)
        switch result {
        case .incomplete:
            return result
        default:
            terminalResult = result
            buffer.removeAll(keepingCapacity: false)
            return result
        }
    }

    public mutating func reset() {
        buffer.removeAll(keepingCapacity: false)
        terminalResult = nil
    }

    /// Pure parser for a complete or partial TLS byte stream.
    public static func parse(_ bytes: Data) -> SNIExtractionResult {
        guard !bytes.isEmpty else { return .incomplete }
        if isHTTPRequest(bytes) { return .notTLS }

        let data = Array(bytes)
        var recordOffset = 0
        var handshake = Data()

        while recordOffset < data.count {
            guard data.count - recordOffset >= 5 else { return .incomplete }
            let contentType = data[recordOffset]
            guard contentType == 22 else { return recordOffset == 0 ? .notTLS : .malformed }
            guard data[recordOffset + 1] == 3 else { return .malformed }
            let recordLength = Int(data[recordOffset + 3]) << 8 | Int(data[recordOffset + 4])
            // RFC 8446 TLSPlaintext limit plus the permitted expansion overhead.
            guard recordLength <= 18_432 else { return .malformed }
            let payloadStart = recordOffset + 5
            let recordEnd = payloadStart + recordLength
            guard recordEnd <= data.count else { return .incomplete }
            handshake.append(contentsOf: data[payloadStart..<recordEnd])
            guard handshake.count <= maximumHandshakeSize + 4 else { return .limitExceeded }

            if handshake.count >= 4 {
                let hello = Array(handshake)
                guard hello[0] == 1 else { return .malformed }
                let handshakeLength = Int(hello[1]) << 16 | Int(hello[2]) << 8 | Int(hello[3])
                guard handshakeLength >= 34 else { return .malformed }
                guard handshakeLength <= maximumHandshakeSize else { return .limitExceeded }
                if handshake.count >= handshakeLength + 4 {
                    return parseClientHello(Array(hello[4..<(handshakeLength + 4)]))
                }
            }
            recordOffset = recordEnd
        }

        return .incomplete
    }

    public static func extract(from bytes: Data) -> String? {
        if case .found(let host) = parse(bytes) { return host }
        return nil
    }

    public static func extractSNI(from bytes: Data) -> String? {
        extract(from: bytes)
    }

    /// Recognizes HTTP as soon as its method prefix arrives; no arbitrary 2 KiB
    /// read or complete-header wait is involved.
    public static func isHTTPRequest(_ bytes: Data) -> Bool {
        guard !bytes.isEmpty else { return false }
        let methods = ["GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "]
        guard let prefix = String(bytes: bytes.prefix(8), encoding: .ascii) else { return false }
        return methods.contains { method in
            method.hasPrefix(prefix) || prefix.hasPrefix(method)
        }
    }

    private static func parseClientHello(_ body: [UInt8]) -> SNIExtractionResult {
        var offset = 0

        func take(_ count: Int) -> ArraySlice<UInt8>? {
            guard count >= 0, offset + count <= body.count else { return nil }
            let result = body[offset..<(offset + count)]
            offset += count
            return result
        }

        func takeLengthPrefixed(lengthBytes: Int) -> ArraySlice<UInt8>? {
            guard let lengthData = take(lengthBytes) else { return nil }
            var length = 0
            for byte in lengthData { length = length << 8 | Int(byte) }
            return take(length)
        }

        // legacy_version + random
        guard take(2 + 32) != nil,
              takeLengthPrefixed(lengthBytes: 1) != nil else { return .malformed }
        guard let cipherSuites = takeLengthPrefixed(lengthBytes: 2), cipherSuites.count >= 2,
              cipherSuites.count.isMultiple(of: 2) else { return .malformed }
        guard let compressionMethods = takeLengthPrefixed(lengthBytes: 1), !compressionMethods.isEmpty else {
            return .malformed
        }

        if offset == body.count { return .noSNI }
        guard let extensions = takeLengthPrefixed(lengthBytes: 2) else { return .malformed }
        let extensionBytes = Array(extensions)
        var extensionOffset = 0

        while extensionOffset < extensionBytes.count {
            guard extensionOffset + 4 <= extensionBytes.count else { return .malformed }
            let type = UInt16(extensionBytes[extensionOffset]) << 8 | UInt16(extensionBytes[extensionOffset + 1])
            let length = Int(extensionBytes[extensionOffset + 2]) << 8 | Int(extensionBytes[extensionOffset + 3])
            extensionOffset += 4
            guard extensionOffset + length <= extensionBytes.count else { return .malformed }
            let value = Array(extensionBytes[extensionOffset..<(extensionOffset + length)])
            extensionOffset += length

            guard type == 0 else { continue }
            guard value.count >= 2 else { return .malformed }
            let listLength = Int(value[0]) << 8 | Int(value[1])
            guard listLength == value.count - 2 else { return .malformed }
            var nameOffset = 2
            while nameOffset < value.count {
                guard nameOffset + 3 <= value.count else { return .malformed }
                let nameType = value[nameOffset]
                let nameLength = Int(value[nameOffset + 1]) << 8 | Int(value[nameOffset + 2])
                nameOffset += 3
                guard nameOffset + nameLength <= value.count else { return .malformed }
                let nameData = value[nameOffset..<(nameOffset + nameLength)]
                nameOffset += nameLength
                if nameType == 0 {
                    guard !nameData.isEmpty,
                          let name = String(bytes: nameData, encoding: .utf8),
                          let normalized = try? DomainList.normalize(name) else { return .malformed }
                    return .found(normalized)
                }
            }
        }

        return .noSNI
    }
}

public enum SNIDirectReason: Equatable, Sendable {
    case noSNI
    case addressNotRouted(String)
    case hostNotInDomainList(String)
    case domainMismatch(sni: String, expected: [String])
}

public enum SNIPolicyDecision: Equatable, Sendable {
    case warp(domain: String, address: String)
    case direct(SNIDirectReason)
}

public struct SNIPolicyEvaluation: Equatable, Sendable {
    public let decision: SNIPolicyDecision
    public let logMessage: String?

    public init(decision: SNIPolicyDecision, logMessage: String?) {
        self.decision = decision
        self.logMessage = logMessage
    }
}

/// Pure exact-IP/SNI verification. In particular, ECH/no-SNI never inherits a
/// WARP decision merely because its destination appeared in a DNS response.
public enum SNIPolicy {
    public static func evaluate(
        sni: String?,
        destinationAddress: String,
        domains: DomainSnapshot,
        routes: RouteSnapshot
    ) -> SNIPolicyEvaluation {
        guard let route = routes.routes.first(where: { $0.address == destinationAddress }) else {
            let reason = SNIDirectReason.addressNotRouted(destinationAddress)
            return SNIPolicyEvaluation(
                decision: .direct(reason),
                logMessage: "SNI policy direct: exact route missing for \(destinationAddress)"
            )
        }
        guard let sni else {
            return SNIPolicyEvaluation(
                decision: .direct(.noSNI),
                logMessage: "SNI policy direct: no SNI/ECH for \(destinationAddress)"
            )
        }
        guard let host = try? DomainList.normalize(sni) else {
            let reason = SNIDirectReason.hostNotInDomainList(sni)
            return SNIPolicyEvaluation(
                decision: .direct(reason),
                logMessage: "SNI policy direct: invalid SNI for \(destinationAddress)"
            )
        }
        guard domains.contains(host) else {
            let reason = SNIDirectReason.hostNotInDomainList(host)
            return SNIPolicyEvaluation(
                decision: .direct(reason),
                logMessage: "SNI policy direct: \(host) is not in domain snapshot"
            )
        }
        guard route.sourceDomains.contains(host) else {
            let reason = SNIDirectReason.domainMismatch(sni: host, expected: route.sourceDomains)
            return SNIPolicyEvaluation(
                decision: .direct(reason),
                logMessage: "SNI policy direct: \(host) does not match exact-IP domain(s) \(route.sourceDomains.joined(separator: ","))"
            )
        }
        return SNIPolicyEvaluation(decision: .warp(domain: host, address: destinationAddress), logMessage: nil)
    }
}
