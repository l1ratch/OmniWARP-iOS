import XCTest
@testable import OmniWARP

final class CoreLogicTests: XCTestCase {
    // MARK: - AmneziaWGParams

    func testZapretPresetMatchesPublishedValues() throws {
        let params = AmneziaWGParams.zapretManager
        XCTAssertEqual(params.jc, 4)
        XCTAssertEqual(params.jmin, 40)
        XCTAssertEqual(params.jmax, 70)
        XCTAssertEqual(params.s1, 0)
        XCTAssertEqual(params.s2, 0)
        XCTAssertEqual([params.h1, params.h2, params.h3, params.h4], [1, 2, 3, 4])
        XCTAssertTrue(params.i1.allSatisfy { $0.isHexDigit })
        XCTAssertTrue(params.i1.count.isMultiple(of: 2))
        XCTAssertNoThrow(try params.validated())
    }

    func testRandomParamsAreValidAndDiffer() throws {
        for _ in 0..<32 {
            let params = AmneziaWGParams.random()
            XCTAssertNoThrow(try params.validated())
            XCTAssertTrue((1...8).contains(params.jc))
            XCTAssertLessThanOrEqual(params.jmin, params.jmax)
            XCTAssertEqual([params.h1, params.h2, params.h3, params.h4], [1, 2, 3, 4])
            XCTAssertEqual(params.s1, 0, "Cloudflare WARP не должен получать случайный handshake padding")
            XCTAssertEqual(params.s2, 0)
            XCTAssertTrue((20...2400).contains(params.i1.count))
        }
        XCTAssertNotEqual(AmneziaWGParams.random(), AmneziaWGParams.random())
    }

    func testParamsRejectBadValues() {
        var params = AmneziaWGParams.zapretManager
        params.jmin = 100
        params.jmax = 10
        XCTAssertThrowsError(try params.validated())

        var hex = AmneziaWGParams.zapretManager
        hex.i1 = "not-hex"
        XCTAssertThrowsError(try hex.validated())

        var headers = AmneziaWGParams.zapretManager
        headers.h2 = headers.h1
        XCTAssertThrowsError(try headers.validated())
    }

    // MARK: - WarpConfig

    private func makeConfig() -> WarpConfig {
        WarpConfig(
            privateKey: "mP5K0dc4q9TtkhZ8fGfB7F0rY0W8mZ6oM0p2mQ7r4U0=",
            peerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            addresses: ["172.16.0.2/32", "2606:4700:110:8a1:1111:2222:3333:4444/128"]
        )
    }

    func testWarpConfigSerializesPlainIPv4DNS() throws {
        // Регрессия: isValidAddress раньше отвергал IPv4 без CIDR,
        // из-за чего DNS 1.1.1.1 ломал validate().
        let config = makeConfig()
        let text = try config.wgQuickConfiguration()
        XCTAssertTrue(text.contains("DNS = 1.1.1.1"))
        XCTAssertTrue(text.contains("PrivateKey = "))
        XCTAssertTrue(text.contains("Jc = 4"))
        XCTAssertTrue(text.contains("I1 = <b 0x"))
        XCTAssertTrue(text.contains("AllowedIPs = 0.0.0.0/0, ::/0"))
    }

    func testWarpConfigRejectsInvalidValues() {
        var bad = makeConfig()
        bad.privateKey = "short"
        XCTAssertThrowsError(try bad.wgQuickConfiguration())

        var noAddress = makeConfig()
        noAddress.addresses = []
        XCTAssertThrowsError(try noAddress.wgQuickConfiguration())
    }

    func testEndpointRoundTrip() throws {
        var config = makeConfig()
        config = config.withEndpoint(host: "188.114.96.1", port: 2408)
        let text = try config.wgQuickConfiguration()
        XCTAssertTrue(text.contains("Endpoint = 188.114.96.1:2408"))
    }

    // MARK: - DomainList

    func testDomainListParsing() {
        let result = DomainList.parseDetailed("""
        # comment
        Example.COM
        *.youtube.com
        googlevideo.com.  # trailing dot
        bad_domain!

        example.com
        """)
        XCTAssertEqual(result.rules.count, 3)
        XCTAssertEqual(result.issues.count, 1)
        XCTAssertTrue(DomainList.contains("example.com", in: result.rules))
        XCTAssertTrue(DomainList.contains("www.example.com", in: result.rules))
        XCTAssertTrue(DomainList.contains("a.youtube.com", in: result.rules))
        XCTAssertFalse(DomainList.contains("youtube.com", in: result.rules)) // wildcard — только поддомены
        XCTAssertTrue(DomainList.contains("googlevideo.com", in: result.rules))
    }

    func testDomainRuleNormalizesHostOnMatch() {
        XCTAssertTrue(DomainList.contains("WWW.Example.COM.", in: ["example.com"]))
        XCTAssertFalse(DomainList.contains("notexample.com", in: ["example.com"]))
    }

    // MARK: - ConfigurationSnapshot

    func testSnapshotJSONRoundTrip() throws {
        let snapshot = ConfigurationSnapshot(
            awgParamsData: try JSONEncoder().encode(AmneziaWGParams.zapretManager),
            warpConfigData: try makeConfig().wgQuickData(),
            domainLists: [DomainListDescriptor(id: "yt", url: URL(string: "https://example.com/yt.lst")!, name: "YouTube")],
            splitTunnelingEnabled: true,
            dnsServers: ["1.1.1.1"]
        )
        let restored = try ConfigurationSnapshot(jsonData: snapshot.jsonData())
        XCTAssertEqual(restored, snapshot)
        XCTAssertEqual(restored.domainLists.first?.name, "YouTube")
        XCTAssertTrue(restored.splitTunnelingEnabled)
    }

    func testSnapshotRejectsUnknownVersion() throws {
        var object = try JSONSerialization.jsonObject(with: ConfigurationSnapshot().jsonData()) as! [String: Any]
        object["version"] = 99
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try ConfigurationSnapshot(jsonData: data))
    }
}
