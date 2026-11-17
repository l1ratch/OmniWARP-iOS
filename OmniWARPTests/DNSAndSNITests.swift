import XCTest
@testable import OmniWARP

final class DNSAndSNITests: XCTestCase {
    // MARK: - DNS codec

    func testDNSQueryRoundTrip() throws {
        let message = DNSMessage(
            header: DNSHeader(id: 0x1234, recursionDesired: true),
            questions: [DNSQuestion(name: "example.com", type: DNSRecordType.a.rawValue)]
        )
        let restored = try DNSMessage(data: message.serialized())
        XCTAssertEqual(restored, message)
        XCTAssertEqual(restored.questions.first?.name, "example.com")
        XCTAssertEqual(restored.header.id, 0x1234)
    }

    func testDNSAnswerWithARecord() throws {
        let answer = try DNSResourceRecord.a(name: "example.com", address: "93.184.216.34", timeToLive: 60)
        let message = DNSMessage(
            header: DNSHeader(id: 7, isResponse: true),
            questions: [DNSQuestion(name: "example.com", type: DNSRecordType.a.rawValue)],
            answers: [answer]
        )
        let restored = try DNSMessage(data: message.serialized())
        XCTAssertEqual(restored.answers.count, 1)
        XCTAssertEqual(restored.answers.first?.data, Data([93, 184, 216, 34]))
        let addresses = restored.realAddresses(domain: "example.com", family: .ipv4)
        XCTAssertEqual(addresses.first?.address, "93.184.216.34")
    }

    func testDNSRejectsTruncatedInput() {
        XCTAssertThrowsError(try DNSMessage(data: Data([0, 1, 0])))
    }

    func testDNSHandlesCompressionPointers() throws {
        // example.com A query + ответ со сжатым именем 0xC00C.
        var bytes: [UInt8] = [
            0x00, 0x2A, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            7, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 3, 0x63, 0x6F, 0x6D, 0,
            0x00, 0x01, 0x00, 0x01
        ]
        bytes += [
            0xC0, 0x0C,             // compressed name -> offset 12
            0x00, 0x01, 0x00, 0x01, // A IN
            0x00, 0x00, 0x00, 0x3C, // TTL 60
            0x00, 0x04,             // rdlength
            1, 2, 3, 4
        ]
        let message = try DNSMessage(data: Data(bytes))
        XCTAssertEqual(message.answers.first?.name, "example.com")
        XCTAssertEqual(message.answers.first?.data, Data([1, 2, 3, 4]))
    }

    // MARK: - Route snapshot

    func testRoutesAreExactHostRoutes() throws {
        let address = try ResolvedAddress(address: "188.114.96.7", timeToLive: 60, sourceDomain: "example.com")
        XCTAssertEqual(address.family.prefixLength, 32)
        let v6 = try ResolvedAddress(address: "2606:4700::6810:1", timeToLive: 60, sourceDomain: "example.com")
        XCTAssertEqual(v6.family.prefixLength, 128)
    }

    // MARK: - SNI

    private func makeClientHello(serverName: String) -> Data {
        var name = Data()
        name.append(0) // host_name
        name.append(contentsOf: UInt16(serverName.utf8.count).bigEndianBytes)
        name.append(contentsOf: serverName.utf8)

        var serverNameList = Data()
        serverNameList.append(contentsOf: UInt16(name.count).bigEndianBytes)
        serverNameList.append(name)

        var sniExtension = Data()
        sniExtension.append(contentsOf: UInt16(0).bigEndianBytes) // server_name
        sniExtension.append(contentsOf: UInt16(serverNameList.count).bigEndianBytes)
        sniExtension.append(serverNameList)

        var body = Data()
        body.append(contentsOf: [0x03, 0x03])                    // TLS 1.2 legacy version
        body.append(contentsOf: [UInt8](repeating: 0xAB, count: 32)) // random
        body.append(0)                                           // session id
        body.append(contentsOf: UInt16(2).bigEndianBytes)
        body.append(contentsOf: [0x13, 0x01])                    // TLS_AES_128_GCM_SHA256
        body.append(1)
        body.append(0)                                           // null compression
        body.append(contentsOf: UInt16(sniExtension.count).bigEndianBytes)
        body.append(sniExtension)

        var handshake = Data()
        handshake.append(1) // client_hello
        handshake.append(contentsOf: UInt32(body.count).bigEndianBytes.suffix(3))
        handshake.append(body)

        var record = Data()
        record.append(contentsOf: [0x16, 0x03, 0x01])
        record.append(contentsOf: UInt16(handshake.count).bigEndianBytes)
        record.append(handshake)
        return record
    }

    func testSNIExtraction() {
        let hello = makeClientHello(serverName: "www.youtube.com")
        XCTAssertEqual(SNIExtractor.extractSNI(from: hello), "www.youtube.com")
        if case .found(let name) = SNIExtractor.parse(hello) {
            XCTAssertEqual(name, "www.youtube.com")
        } else {
            XCTFail("SNI не найден")
        }
    }

    func testSNIWorksAcrossFragments() {
        let hello = makeClientHello(serverName: "discord.com")
        var extractor = SNIExtractor()
        var result: SNIExtractionResult = .incomplete
        for byte in hello {
            result = extractor.append(Data([byte]))
        }
        XCTAssertEqual(result, .found("discord.com"))
    }

    func testSNIHandlesHTTPWithoutBuffering() {
        let http = Data("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)
        XCTAssertEqual(SNIExtractor.parse(http), .notTLS)
        XCTAssertTrue(SNIExtractor.isHTTPRequest(http))
    }

    func testSNIPolicyMismatchGoesDirect() {
        let domains = DomainSnapshot(
            rules: DomainList.parse("youtube.com"),
            revision: 1,
            loadedAt: Date()
        )
        let routes = RouteSnapshot(
            routes: [IPRoute(
                address: "188.114.96.7",
                prefixLength: 32,
                sourceDomains: ["youtube.com"],
                expiresAt: Date().addingTimeInterval(60)
            )],
            revision: 1,
            updatedAt: Date()
        )
        let mismatch = SNIPolicy.evaluate(
            sni: "cdn.other.net",
            destinationAddress: "188.114.96.7",
            domains: domains,
            routes: routes
        )
        guard case .direct = mismatch.decision else {
            return XCTFail("SNI mismatch должен уводить в direct: \(mismatch)")
        }

        let match = SNIPolicy.evaluate(
            sni: "youtube.com",
            destinationAddress: "188.114.96.7",
            domains: domains,
            routes: routes
        )
        guard case .warp(let domain, _) = match.decision else {
            return XCTFail("Совпадающий SNI должен идти в WARP: \(match)")
        }
        XCTAssertEqual(domain, "youtube.com")

        let noSNI = SNIPolicy.evaluate(
            sni: nil,
            destinationAddress: "188.114.96.7",
            domains: domains,
            routes: routes
        )
        guard case .direct(let reason) = noSNI.decision else {
            return XCTFail("ECH/no-SNI не должен наследовать WARP-решение")
        }
        XCTAssertEqual(reason, .noSNI)
    }
}

private extension UInt16 {
    var bigEndianBytes: [UInt8] {
        [UInt8((self >> 8) & 0xFF), UInt8(self & 0xFF)]
    }
}

private extension UInt32 {
    var bigEndianBytes: [UInt8] {
        [UInt8((self >> 24) & 0xFF), UInt8((self >> 16) & 0xFF), UInt8((self >> 8) & 0xFF), UInt8(self & 0xFF)]
    }
}
