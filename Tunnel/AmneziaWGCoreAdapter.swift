//
//  AmneziaWGCoreAdapter.swift
//  OmniWARP — Tunnel
//
//  Честный boundary к userspace-ядру AmneziaWG. Никакого fake success: пока ядро
//  не слинковано, доступность — `.unavailable(...)`, и любая попытка проверки
//  возвращает ошибку, а не «кандидат работает».
//
//  Реальная точка подключения ядра
//  ------------------------------
//  Используется https://github.com/amnezia-vpn/amneziawg-apple @ 3bca528
//  (Swift package product/target = `WireGuardKit`, хотя внутри именно AWG).
//  Статическая сборка Go-бриджа: `Sources/WireGuardKitGo/out/libwg-go.a`
//  (собирается `scripts/build-awg-core.sh`, SwiftPM сам её НЕ собирает).
//  Всё работает внутри процесса Network Extension, БЕЗ fork/exec/внешних
//  процессов. Go runtime линкуется статически, `libresolv` — системная.
//
//  Ожидаемые C-символы (`Sources/WireGuardKitGo/wireguard.h`, `api-apple.go`)
//  ------------------------------------------------------------------------
//    typedef void(*logger_fn_t)(void *context, int level, const char *msg);
//    void   wgSetLogger(void *context, logger_fn_t logger_fn);
//    int    wgTurnOn(const char *settings, int32_t tun_fd);
//    void   wgTurnOff(int handle);
//    int64_t wgSetConfig(int handle, const char *settings);
//    char  *wgGetConfig(int handle);                    // UAPI-текст, нужен free()
//    void   wgBumpSockets(int handle);
//    void   wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
//    const char *wgVersion();
//
//  Почему адаптер НЕ дёргает C напрямую
//  ----------------------------------
//  `WireGuardKitGo` не экспортируется как продукт SwiftPM (см. `Package.swift`),
//  поэтому из клиентского кода C-функции недоступны. Но главное — заботливые
//  обязанности живут в Swift-слое: поиск utun fd, `setTunnelNetworkSettings`,
//  DNS-резолв endpoint'ов, реакция на смену сети. Их не надо дублировать.
//  Поэтому boundary здесь = публичный Swift API `WireGuardAdapter`:
//    * `WireGuardAdapter(with: NEPacketTunnelProvider, logHandler:)`
//    * `start(tunnelConfiguration:completionHandler:)`
//    * `stop(completionHandler:)`
//    * `getRuntimeConfiguration(completionHandler:)` → `wgGetConfig` (UAPI)
//  Из UAPI-выгрузки берутся `last_handshake_time_sec`/`last_handshake_time_nsec`
//  (доказательство handshake) и `rx_bytes`/`tx_bytes` (статистика).
//
//  Сборка TunnelConfiguration: wg-quick текст НЕ подходит
//  ------------------------------------------------------
//  `TunnelConfiguration+WgQuickConfig.swift` (с `init(fromWgQuickConfig:)`)
//  лежит в `Sources/Shared/Model/` и в SwiftPM-продукт `WireGuardKit` НЕ входит.
//  Поэтому конфиг собирается структурно из `AmneziaWGCoreConfiguration`
//  (публичные `InterfaceConfiguration`/`PeerConfiguration`/`PrivateKey`/…).
//  Таблица соответствия AWG → `InterfaceConfiguration` (дальше UAPI):
//    jc   → junkPacketCount              ("jc=")
//    jmin → junkPacketMinSize            ("jmin=")
//    jmax → junkPacketMaxSize            ("jmax=")
//    s1   → initPacketJunkSize           ("s1=")
//    s2   → responsePacketJunkSize       ("s2=")
//    s3   → cookieReplyPacketJunkSize    ("s3=")
//    s4   → transportPacketJunkSize      ("s4=")
//    h1   → initPacketMagicHeader        ("h1=")
//    h2   → responsePacketMagicHeader    ("h2=")
//    h3   → underloadPacketMagicHeader   ("h3=")
//    h4   → transportPacketMagicHeader   ("h4=")
//    i1   → specialJunk1                 ("i1=")
//    i2…i5→ specialJunk2…specialJunk5
//    header_protection_key → headerProtectionKey
//    content_padding_addition/rekey_*/keepalive_timeout/
//    max_handshake_attempts/random_trailers/disable_cookies — как в upstream.
//
//  Для `PacketTunnelProvider` в конце файла есть `WgQuickConfigParser`:
//  он разбирает наш собственный wg-quick/AmneziaWG текст (`WarpConfig.wgQuickData()`)
//  в тот же структурный `TunnelConfiguration` (включая `I1 = <b 0x…>` как есть).
//  И `WarpConfigCoreConfigurationProvider` — конвертация `Shared/WarpConfig.swift`
//  в нейтральную модель ядра (используется и app-, и extension-таргетами).
//
//  Границы возможного на iOS
//  -------------------------
//  1. Второй NE/utun одновременно поднять нельзя. Тестовый движок создаётся
//     только внутри уже активного `NEPacketTunnelProvider`, последовательно:
//     suspend production → start тестового → handshake/stats → stop → restore.
//     Параллельного перебора здесь нет и не обещается.
//  2. Сокеты самого extension обходят его собственный туннель, поэтому
//     `probeRTT`/`probeHTTPS` в extension-адаптере честно `.unsupported(...)`.
//     HTTPS через туннель делает app-side драйвер (`TunnelTestDriving`):
//     временно поднять NE с default route и выполнить URLSession к
//     `https://www.cloudflare.com/cdn-cgi/trace`.
//  3. ICMP raw socket не используется и не эмулируется.
//

import Foundation
import Network
import NetworkExtension

#if canImport(WireGuardKit)
import WireGuardKit
#endif

// MARK: - Нейтральная модель конфигурации ядра

/// Структурное описание конфига ядра (без wg-quick текста).
///
/// Заполняется провайдером из `Shared/WarpConfig.swift`; адаптер не знает
/// точных полей shared-модели, поэтому её смена ломает только провайдера.
public struct AmneziaWGCoreConfiguration: Sendable, Equatable {
    /// Ключ в hex (как принимает UAPI) либо в base64.
    public var privateKeyHex: String?
    public var privateKeyBase64: String?
    /// CIDR-адреса интерфейса (`"172.16.0.2/32"`).
    public var addresses: [String]
    public var dnsServers: [String]
    public var mtu: UInt16?
    public var listenPort: UInt16?
    public var obfuscation: Obfuscation
    public var peers: [Peer]

    public struct Peer: Sendable, Equatable {
        public var publicKeyHex: String?
        public var publicKeyBase64: String?
        public var presharedKeyHex: String?
        public var presharedKeyBase64: String?
        /// CIDR allowed IPs; для проверки HTTPS через туннель нужны default
        /// routes (`0.0.0.0/0`, `::/0`).
        public var allowedIPs: [String]
        /// Endpoint пира. Для тестового туннеля всегда подставляется endpoint
        /// проверяемого кандидата (даже если в базовом конфиге он другой).
        public var endpoint: CandidateTarget?
        /// `persistent_keepalive_interval` (UAPI принимает строку).
        public var persistentKeepalive: UInt16?

        public init(endpoint: CandidateTarget? = nil,
                    publicKeyHex: String? = nil,
                    publicKeyBase64: String? = nil,
                    presharedKeyHex: String? = nil,
                    presharedKeyBase64: String? = nil,
                    allowedIPs: [String] = ["0.0.0.0/0", "::/0"],
                    persistentKeepalive: UInt16? = 25) {
            self.endpoint = endpoint
            self.publicKeyHex = publicKeyHex
            self.publicKeyBase64 = publicKeyBase64
            self.presharedKeyHex = presharedKeyHex
            self.presharedKeyBase64 = presharedKeyBase64
            self.allowedIPs = allowedIPs
            self.persistentKeepalive = persistentKeepalive
        }
    }

    /// AWG-параметры обфускации. Все значения проходят в UAPI как есть.
    public struct Obfuscation: Sendable, Equatable {
        public var jc: UInt16?
        public var jmin: UInt16?
        public var jmax: UInt16?
        public var s1: UInt16?
        public var s2: UInt16?
        public var s3: UInt16?
        public var s4: UInt16?
        /// `h1…h4` — magic header'ы, передаются строкой (как в AWG UAPI).
        public var h1: String?
        public var h2: String?
        public var h3: String?
        public var h4: String?
        /// `i1…i5` — спец-мусор в UAPI-формате, например `<b 0xdeadbeef>`
        /// (префикс добавляется провайдером/парсером, не адаптером).
        public var i1: String?
        public var i2: String?
        public var i3: String?
        public var i4: String?
        public var i5: String?
        public var headerProtectionKeyHex: String?
        public var contentPaddingAddition: String?
        public var rekeyAfterTime: String?
        public var rekeyTimeout: String?
        public var rejectAfterTime: String?
        public var keepaliveTimeout: String?
        public var maxHandshakeAttempts: String?
        public var randomTrailers: Bool?
        public var disableCookies: Bool?

        public init(jc: UInt16? = nil,
                    jmin: UInt16? = nil,
                    jmax: UInt16? = nil,
                    s1: UInt16? = nil,
                    s2: UInt16? = nil,
                    s3: UInt16? = nil,
                    s4: UInt16? = nil,
                    h1: String? = nil,
                    h2: String? = nil,
                    h3: String? = nil,
                    h4: String? = nil,
                    i1: String? = nil,
                    i2: String? = nil,
                    i3: String? = nil,
                    i4: String? = nil,
                    i5: String? = nil,
                    headerProtectionKeyHex: String? = nil,
                    contentPaddingAddition: String? = nil,
                    rekeyAfterTime: String? = nil,
                    rekeyTimeout: String? = nil,
                    rejectAfterTime: String? = nil,
                    keepaliveTimeout: String? = nil,
                    maxHandshakeAttempts: String? = nil,
                    randomTrailers: Bool? = nil,
                    disableCookies: Bool? = nil) {
            self.jc = jc
            self.jmin = jmin
            self.jmax = jmax
            self.s1 = s1
            self.s2 = s2
            self.s3 = s3
            self.s4 = s4
            self.h1 = h1
            self.h2 = h2
            self.h3 = h3
            self.h4 = h4
            self.i1 = i1
            self.i2 = i2
            self.i3 = i3
            self.i4 = i4
            self.i5 = i5
            self.headerProtectionKeyHex = headerProtectionKeyHex
            self.contentPaddingAddition = contentPaddingAddition
            self.rekeyAfterTime = rekeyAfterTime
            self.rekeyTimeout = rekeyTimeout
            self.rejectAfterTime = rejectAfterTime
            self.keepaliveTimeout = keepaliveTimeout
            self.maxHandshakeAttempts = maxHandshakeAttempts
            self.randomTrailers = randomTrailers
            self.disableCookies = disableCookies
        }

        public static let empty = Obfuscation()
    }

    public init(privateKeyHex: String? = nil,
                privateKeyBase64: String? = nil,
                addresses: [String],
                dnsServers: [String] = [],
                mtu: UInt16? = nil,
                listenPort: UInt16? = nil,
                obfuscation: Obfuscation = .empty,
                peers: [Peer]) {
        self.privateKeyHex = privateKeyHex
        self.privateKeyBase64 = privateKeyBase64
        self.addresses = addresses
        self.dnsServers = dnsServers
        self.mtu = mtu
        self.listenPort = listenPort
        self.obfuscation = obfuscation
        self.peers = peers
    }
}

// MARK: - Провайдер конфигурации

/// Переводит `Shared/WarpConfig` + endpoint кандидата в структурную модель ядра.
/// Реализуется интеграционным слоем (PacketTunnelProvider/app), которому известны
/// фактические поля `WarpConfig`/`AmneziaWGParams`.
public protocol AmneziaWGCoreConfigurationProviding {
    func coreConfiguration(for configuration: WarpConfig,
                           target: CandidateTarget) throws -> AmneziaWGCoreConfiguration
}

/// Провайдер-замыкание: удобно для интеграции и для тестов.
public struct ClosureCoreConfigurationProvider: AmneziaWGCoreConfigurationProviding {
    public let build: (WarpConfig, CandidateTarget) throws -> AmneziaWGCoreConfiguration

    public init(build: @escaping (WarpConfig, CandidateTarget) throws -> AmneziaWGCoreConfiguration) {
        self.build = build
    }

    public func coreConfiguration(for configuration: WarpConfig,
                                  target: CandidateTarget) throws -> AmneziaWGCoreConfiguration {
        try build(configuration, target)
    }
}

// MARK: - Сводка о ядре

public enum AmneziaWGCoreAdapter {
    /// `true`, если пакет WireGuardKit реально слинкован в этот target.
    public static var isLinked: Bool {
        #if canImport(WireGuardKit)
        return true
        #else
        return false
        #endif
    }

    /// Описание ядра (версию `wgVersion()` SwiftPM-клиент получить не может).
    public static let backend = WarpEngineBackend(identifier: "amneziawg-go (WireGuardKit)",
                                                  inTunnelRTT: false,
                                                  inTunnelHTTPS: false)

    /// Ожидаемые C-символы из `wireguard.h` — документация точки линковки.
    public static let expectedCSymbols: [String] = [
        "wgSetLogger(void *context, logger_fn_t logger_fn)",
        "wgTurnOn(const char *settings, int32_t tun_fd) -> int",
        "wgTurnOff(int handle)",
        "wgSetConfig(int handle, const char *settings) -> int64_t",
        "wgGetConfig(int handle) -> char *",
        "wgBumpSockets(int handle)",
        "wgDisableSomeRoamingForBrokenMobileSemantics(int handle)",
        "wgVersion() -> const char *"
    ]

    /// Ключи UAPI-выгрузки `wgGetConfig`, которые адаптер реально читает.
    public static let consumedUAPIKeys: [String] = [
        "private_key", "listen_port",
        "public_key", "endpoint",
        "last_handshake_time_sec", "last_handshake_time_nsec",
        "rx_bytes", "tx_bytes", "persistent_keepalive_interval"
    ]

    /// Текст причины недоступности ядра (показывается в UI/отчёте).
    public static let unavailableReason = """
    Ядро AmneziaWG недоступно: WireGuardKit не слинкован в этот target. \
    Добавьте пакет amneziawg-apple (WireGuardKit) и соберите libwg-go.a \
    скриптом scripts/build-awg-core.sh. Проверки не выполняются, успех не имитируется.
    """

    /// Доступность ядра с точки зрения линковки.
    public static var linkedAvailability: WarpEngineAvailability {
        #if canImport(WireGuardKit)
        return .available(backend)
        #else
        return .unavailable(unavailableReason)
        #endif
    }
}

// MARK: - Реализация поверх WireGuardKit

#if canImport(WireGuardKit)

/// Сборка `TunnelConfiguration` структурно (wg-quick парсер в SwiftPM-продукте
/// недоступен, поэтому текстовый конфиг здесь не используется).
enum WireGuardKitConfigFactory {
    static func makeTunnelConfiguration(from configuration: AmneziaWGCoreConfiguration,
                                        name: String = "OmniWARP") throws -> TunnelConfiguration {
        guard let privateKey = makePrivateKey(hex: configuration.privateKeyHex,
                                              base64: configuration.privateKeyBase64) else {
            throw WarpEngineError.configurationRejected("невалидный private key (нужен hex или base64)")
        }
        guard !configuration.addresses.isEmpty else {
            throw WarpEngineError.configurationRejected("нет адресов интерфейса")
        }
        guard !configuration.peers.isEmpty else {
            throw WarpEngineError.configurationRejected("нет peer-конфигурации")
        }

        var interface = InterfaceConfiguration(privateKey: privateKey)
        interface.addresses = try configuration.addresses.map { try parseRange($0, label: "address") }
        interface.dns = try configuration.dnsServers.map { try parseDNS($0) }
        interface.mtu = configuration.mtu
        interface.listenPort = configuration.listenPort
        applyObfuscation(configuration.obfuscation, to: &interface)

        let peers = try configuration.peers.map { try makePeer($0) }
        // В upstream конструкторе `fatalError` при одинаковых public key —
        // проверяем заранее, чтобы не уронить процесс.
        let uniqueKeys = Set(peers.map { $0.publicKey })
        guard uniqueKeys.count == peers.count else {
            throw WarpEngineError.configurationRejected("дублируются public key пиров")
        }
        return TunnelConfiguration(name: name, interface: interface, peers: peers)
    }

    private static func makePeer(_ peer: AmneziaWGCoreConfiguration.Peer) throws -> PeerConfiguration {
        let endpointLabel = peer.endpoint?.endpointString ?? "(endpoint не задан)"
        guard let publicKey = makePublicKey(hex: peer.publicKeyHex, base64: peer.publicKeyBase64) else {
            throw WarpEngineError.configurationRejected("невалидный public key пира для \(endpointLabel)")
        }
        var configuration = PeerConfiguration(publicKey: publicKey)
        if let preshared = makePreSharedKey(hex: peer.presharedKeyHex, base64: peer.presharedKeyBase64) {
            configuration.preSharedKey = preshared
        }
        configuration.allowedIPs = try peer.allowedIPs.map { try parseRange($0, label: "allowed_ip") }
        if let peerEndpoint = peer.endpoint {
            // Модульная квалификация намеренная: в `Shared/` уже есть вложенный
            // `WarpRegistrar.Endpoint`, и явное `WireGuardKit.Endpoint` защищает
            // от будущего одноимённого типа верхнего уровня в нашем модуле.
            guard let endpoint = WireGuardKit.Endpoint(from: peerEndpoint.endpointString) else {
                throw WarpEngineError.configurationRejected("невалидный endpoint \(peerEndpoint.endpointString)")
            }
            configuration.endpoint = endpoint
        }
        if let keepalive = peer.persistentKeepalive {
            configuration.persistentKeepAlive = String(keepalive)
        }
        return configuration
    }

    private static func applyObfuscation(_ obfuscation: AmneziaWGCoreConfiguration.Obfuscation,
                                         to interface: inout InterfaceConfiguration) {
        interface.junkPacketCount = obfuscation.jc
        interface.junkPacketMinSize = obfuscation.jmin
        interface.junkPacketMaxSize = obfuscation.jmax
        interface.initPacketJunkSize = obfuscation.s1
        interface.responsePacketJunkSize = obfuscation.s2
        interface.cookieReplyPacketJunkSize = obfuscation.s3
        interface.transportPacketJunkSize = obfuscation.s4
        interface.initPacketMagicHeader = obfuscation.h1
        interface.responsePacketMagicHeader = obfuscation.h2
        interface.underloadPacketMagicHeader = obfuscation.h3
        interface.transportPacketMagicHeader = obfuscation.h4
        interface.specialJunk1 = obfuscation.i1
        interface.specialJunk2 = obfuscation.i2
        interface.specialJunk3 = obfuscation.i3
        interface.specialJunk4 = obfuscation.i4
        interface.specialJunk5 = obfuscation.i5
        if let headerKeyHex = obfuscation.headerProtectionKeyHex {
            interface.headerProtectionKey = PrivateKey(hexKey: headerKeyHex)
        }
        interface.contentPaddingAddition = obfuscation.contentPaddingAddition
        interface.rekeyAfterTime = obfuscation.rekeyAfterTime
        interface.rekeyTimeout = obfuscation.rekeyTimeout
        interface.rejectAfterTime = obfuscation.rejectAfterTime
        interface.keepaliveTimeout = obfuscation.keepaliveTimeout
        interface.maxHandshakeAttempts = obfuscation.maxHandshakeAttempts
        if let randomTrailers = obfuscation.randomTrailers {
            interface.randomTrailers = randomTrailers ? "1" : "0"
        }
        if let disableCookies = obfuscation.disableCookies {
            interface.disableCookies = disableCookies ? "1" : "0"
        }
    }

    private static func parseRange(_ string: String, label: String) throws -> IPAddressRange {
        guard let range = IPAddressRange(from: string) else {
            throw WarpEngineError.configurationRejected("невалидный \(label): \(string)")
        }
        return range
    }

    private static func parseDNS(_ string: String) throws -> DNSServer {
        guard let server = DNSServer(from: string) else {
            throw WarpEngineError.configurationRejected("невалидный DNS-сервер: \(string)")
        }
        return server
    }

    private static func makePrivateKey(hex: String?, base64: String?) -> PrivateKey? {
        if let hex, !hex.isEmpty, let key = PrivateKey(hexKey: hex) { return key }
        if let base64, !base64.isEmpty, let key = PrivateKey(base64Key: base64) { return key }
        return nil
    }

    private static func makePublicKey(hex: String?, base64: String?) -> PublicKey? {
        if let hex, !hex.isEmpty, let key = PublicKey(hexKey: hex) { return key }
        if let base64, !base64.isEmpty, let key = PublicKey(base64Key: base64) { return key }
        return nil
    }

    private static func makePreSharedKey(hex: String?, base64: String?) -> PreSharedKey? {
        if let hex, !hex.isEmpty, let key = PreSharedKey(hexKey: hex) { return key }
        if let base64, !base64.isEmpty, let key = PreSharedKey(base64Key: base64) { return key }
        return nil
    }
}

// MARK: - Адаптерный слой над callback-API

/// Одноразовое продолжение: защита от двойного resume (completion может прийти
/// позже таймаута).
private final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var resumed = false

    func resume(_ continuation: CheckedContinuation<Void, Error>, with result: Result<Void, Error>) {
        lock.lock()
        let first = !resumed
        resumed = true
        lock.unlock()
        guard first else { return }
        continuation.resume(with: result)
    }
}

private func startAdapter(_ adapter: WireGuardAdapter,
                          configuration: TunnelConfiguration,
                          timeout: TimeInterval) async throws {
    let box = ResumeOnce()
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            box.resume(continuation, with: .failure(WarpEngineError.probeTimedOut))
        }
        adapter.start(tunnelConfiguration: configuration) { error in
            if let error {
                box.resume(continuation, with: .failure(
                    WarpEngineError.configurationRejected(String(describing: error))))
            } else {
                box.resume(continuation, with: .success(()))
            }
        }
    }
}

private func stopAdapter(_ adapter: WireGuardAdapter, timeout: TimeInterval) async {
    let box = ResumeOnce()
    _ = try? await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            box.resume(continuation, with: .success(()))
        }
        adapter.stop { _ in
            // `invalidState` при повторном stop допустим: цель — остановить ядро.
            box.resume(continuation, with: .success(()))
        }
    }
}

private func readRuntimeConfiguration(_ adapter: WireGuardAdapter) async -> String? {
    await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
        adapter.getRuntimeConfiguration { settings in
            continuation.resume(returning: settings)
        }
    }
}

// MARK: - Движок

/// Движок AmneziaWG поверх `WireGuardAdapter`.
///
/// ВАЖНО: перед `start` продовый туннель должен быть остановлен (или передан
/// `productionSuspender`). Два `WireGuardAdapter` с разными ядрами на одном
/// utun одновременно недопустимы — это не проверяется автоматически.
public final class WireGuardKitEngine: WarpEngine, @unchecked Sendable {
    public let backend = AmneziaWGCoreAdapter.backend

    public typealias ProviderResolver = @Sendable () -> NEPacketTunnelProvider?
    public typealias ProductionHook = @Sendable () async -> Void

    private enum State: Equatable {
        case stopped
        case starting
        case running
        case stopping
    }

    private let providerResolver: ProviderResolver
    private let parametersProvider: any AmneziaWGCoreConfigurationProviding
    private let productionSuspender: ProductionHook?
    private let productionRestorer: ProductionHook?
    private let adapterStartTimeout: TimeInterval
    private let adapterStopTimeout: TimeInterval
    private let handshakePollInterval: TimeInterval

    private let lock = NSLock()
    private var state: State = .stopped
    private var adapter: WireGuardAdapter?
    private var startedAtWall: Date?
    private var currentTarget: CandidateTarget?
    private var restoreProductionOnStop = false

    public init(providerResolver: @escaping ProviderResolver,
                parametersProvider: any AmneziaWGCoreConfigurationProviding,
                productionSuspender: ProductionHook? = nil,
                productionRestorer: ProductionHook? = nil,
                adapterStartTimeout: TimeInterval = 12.0,
                adapterStopTimeout: TimeInterval = 5.0,
                handshakePollInterval: TimeInterval = 0.25) {
        self.providerResolver = providerResolver
        self.parametersProvider = parametersProvider
        self.productionSuspender = productionSuspender
        self.productionRestorer = productionRestorer
        self.adapterStartTimeout = adapterStartTimeout
        self.adapterStopTimeout = adapterStopTimeout
        self.handshakePollInterval = handshakePollInterval
    }

    public func start(configuration: WarpConfig,
                      target: CandidateTarget,
                      restoreProductionOnStop: Bool) async throws {
        lock.lock()
        let currentState = state
        if currentState == .stopped {
            state = .starting
        }
        lock.unlock()
        guard currentState == .stopped else {
            throw WarpEngineError.invalidState("start допустим только из stopped (сейчас \(currentState))")
        }

        do {
            if restoreProductionOnStop, let productionSuspender {
                await productionSuspender()
            }

            guard let provider = providerResolver() else {
                throw WarpEngineError.engineUnavailable(
                    "нет активного NEPacketTunnelProvider: тестовый utun вне extension поднять нельзя")
            }
            let parameters = try parametersProvider.coreConfiguration(for: configuration, target: target)
            var forcedParameters = parameters
            // Тестовый движок всегда идёт на проверяемый endpoint, даже если
            // провайдер вернул базовый конфиг с другим адресом.
            if !forcedParameters.peers.isEmpty,
               forcedParameters.peers[0].endpoint == nil || forcedParameters.peers.count == 1 {
                forcedParameters.peers[0].endpoint = target
            }
            let tunnelConfiguration = try WireGuardKitConfigFactory.makeTunnelConfiguration(from: forcedParameters)

            let adapter = WireGuardAdapter(with: provider) { level, message in
                switch level {
                case .verbose: NSLog("[OmniWARP][awg] %@", message)
                case .error: NSLog("[OmniWARP][awg:error] %@", message)
                @unknown default: NSLog("[OmniWARP][awg] %@", message)
                }
            }

            lock.lock()
            self.adapter = adapter
            startedAtWall = Date()
            currentTarget = target
            self.restoreProductionOnStop = restoreProductionOnStop
            lock.unlock()

            try await startAdapter(adapter, configuration: tunnelConfiguration, timeout: adapterStartTimeout)

            lock.lock()
            state = .running
            lock.unlock()
        } catch {
            await shutdownAdapter()
            let shouldRestore = restoreProductionOnStop
            lock.lock()
            state = .stopped
            startedAtWall = nil
            currentTarget = nil
            self.restoreProductionOnStop = false
            lock.unlock()
            // Если продовый туннель был погашен, но тестовый не поднялся —
            // возвращаем продовый, иначе пользователь останется без сети.
            if shouldRestore, let productionRestorer {
                await productionRestorer()
            }
            throw error
        }
    }

    public func stop() async {
        lock.lock()
        let shouldRestore = restoreProductionOnStop
        restoreProductionOnStop = false
        let hadWork = state != .stopped
        if hadWork { state = .stopping }
        lock.unlock()

        guard hadWork else { return }
        await shutdownAdapter()

        lock.lock()
        state = .stopped
        startedAtWall = nil
        currentTarget = nil
        lock.unlock()

        if shouldRestore, let productionRestorer {
            await productionRestorer()
        }
    }

    public func performHandshake(timeout: TimeInterval) async throws -> HandshakeOutcome {
        lock.lock()
        let isRunning = state == .running
        let adapter = self.adapter
        let startWall = startedAtWall
        let target = currentTarget
        lock.unlock()

        guard isRunning, let adapter, let startWall else {
            throw WarpEngineError.invalidState("handshake можно ждать только у запущенного движка")
        }

        let started = WarpMonotonicClock.now()
        let deadline = started + max(0.5, timeout)
        let pollInterval = max(0.1, handshakePollInterval)

        while WarpMonotonicClock.now() < deadline {
            if Task.isCancelled { throw WarpEngineError.cancelled }

            if let text = await readRuntimeConfiguration(adapter),
               let runtime = WarpRuntimeConfiguration(uapi: text),
               let peer = runtime.freshHandshake(),
               Self.endpointMatches(peer: peer, target: target) {
                return HandshakeOutcome(observedAt: Date(),
                                        lastHandshakeAt: Date(),
                                        attemptDurationMs: WarpMonotonicClock.millisecondsSince(started),
                                        source: .runtimeConfiguration,
                                        rxBytes: runtime.totalRxBytes,
                                        txBytes: runtime.totalTxBytes)
            }

            do {
                try await Task.sleep(nanoseconds: UInt64(pollInterval * 1_000_000_000))
            } catch {
                throw WarpEngineError.cancelled
            }
        }
        throw WarpEngineError.handshakeTimeout
    }

    public func probeRTT(_ plan: RTTProbePlan) async -> RTTProbeOutcome {
        .unsupported("Внутри extension нет userspace-стека и пути данных в туннель: " +
                     "UDP/TCP RTT внутри туннеля измеряет app-side драйвер, не ядро.")
    }

    public func probeHTTPS(_ plan: HTTPSProbePlan) async -> HTTPSProbeOutcome {
        .unsupported("Сокеты Network Extension обходят его собственный туннель. " +
                     "HTTPS-пробу выполняет app-side драйвер: тестовый NE с default route + " +
                     "URLSession к https://www.cloudflare.com/cdn-cgi/trace.")
    }

    public func snapshotStats() async -> WarpEngineStats? {
        lock.lock()
        let adapter = self.adapter
        lock.unlock()
        guard let adapter else { return nil }

        guard let text = await readRuntimeConfiguration(adapter),
              let runtime = WarpRuntimeConfiguration(uapi: text) else { return nil }

        return WarpEngineStats(sampledAt: Date(),
                               rxBytes: runtime.totalRxBytes,
                               txBytes: runtime.totalTxBytes,
                               lastHandshakeAt: runtime.hasConfirmedHandshake ? Date() : nil,
                               endpoint: runtime.primaryPeer?.endpoint)
    }

    // MARK: - Внутреннее

    private func shutdownAdapter() async {
        lock.lock()
        let adapter = self.adapter
        self.adapter = nil
        lock.unlock()
        guard let adapter else { return }
        await stopAdapter(adapter, timeout: adapterStopTimeout)
    }

    private static func endpointMatches(peer: WarpRuntimeConfiguration.Peer,
                                        target: CandidateTarget?) -> Bool {
        guard let target else { return true }
        guard let peerTarget = peer.endpointTarget else { return true }
        // Сравниваем по хосту/порту; несовпадение означает, что handshake
        // относится к другому peer'у, и его нельзя приписывать кандидату.
        return peerTarget == target
    }
}

// MARK: - Фабрика

/// Фабрика движков для последовательной проверки кандидатов внутри extension.
public final class WireGuardKitEngineFactory: WarpEngineFactory {
    public typealias ProviderResolver = WireGuardKitEngine.ProviderResolver
    public typealias ProductionHook = WireGuardKitEngine.ProductionHook

    private let parametersProvider: any AmneziaWGCoreConfigurationProviding
    private let providerResolver: ProviderResolver
    private let productionSuspender: ProductionHook?
    private let productionRestorer: ProductionHook?

    /// - Parameters:
    ///   - parametersProvider: перевод `WarpConfig` → структурная модель ядра.
    ///     По умолчанию `WarpConfigCoreConfigurationProvider` (Shared/WarpConfig).
    ///   - providerResolver: возвращает текущий `NEPacketTunnelProvider`
    ///     (например, `{ [weak provider] in provider }` из PacketTunnelProvider).
    ///   - productionSuspender: останавливает продовый туннель перед тестом.
    ///   - productionRestorer: поднимает его обратно после теста.
    public init(parametersProvider: any AmneziaWGCoreConfigurationProviding = WarpConfigCoreConfigurationProvider(),
                providerResolver: @escaping ProviderResolver,
                productionSuspender: ProductionHook? = nil,
                productionRestorer: ProductionHook? = nil) {
        self.parametersProvider = parametersProvider
        self.providerResolver = providerResolver
        self.productionSuspender = productionSuspender
        self.productionRestorer = productionRestorer
    }

    public var availability: WarpEngineAvailability {
        AmneziaWGCoreAdapter.linkedAvailability
    }

    public func makeEngine() throws -> any WarpEngine {
        guard providerResolver() != nil else {
            throw WarpEngineError.engineUnavailable(
                "NEPacketTunnelProvider не найден: ядро нельзя поднять вне Network Extension")
        }
        return WireGuardKitEngine(providerResolver: providerResolver,
                                  parametersProvider: parametersProvider,
                                  productionSuspender: productionSuspender,
                                  productionRestorer: productionRestorer)
    }
}

// MARK: - TunnelTestDriving внутри extension

/// Драйвер проверки внутри extension: даёт handshake/stats от реального ядра,
/// но НЕ обещает HTTPS/RTT через туннель (см. ограничения в шапке файла).
public final class WireGuardKitTunnelTestDriver: TunnelTestDriving {
    private let factory: WireGuardKitEngineFactory

    public init(factory: WireGuardKitEngineFactory) {
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
        try await WarpEngineTestDriver(factory: factory).startTestSession(request)
    }
}

// MARK: - Парсер wg-quick/AmneziaWG текста

/// Разбирает wg-quick/AmneziaWG текст (`WarpConfig.wgQuickConfiguration()`)
/// в структурный `TunnelConfiguration`.
///
/// Зачем свой парсер: `TunnelConfiguration(fromWgQuickConfig:)` не входит в
/// SwiftPM-продукт `WireGuardKit` (он в `Sources/Shared`), поэтому extension
/// не может его использовать. Парсер строгий и поддерживает ровно те ключи,
/// которые генерирует наша shared-модель, плюс s3/s4/i2…i5 на будущее.
public enum WgQuickConfigParser {
    /// Строит `TunnelConfiguration` (публичный API WireGuardKit).
    public static func parse(_ text: String, name: String = "OmniWARP") throws -> TunnelConfiguration {
        try WireGuardKitConfigFactory.makeTunnelConfiguration(from: parseCoreConfiguration(text), name: name)
    }

    /// Промежуточная нейтральная модель (без WireGuardKit-типов).
    public static func parseCoreConfiguration(_ text: String) throws -> AmneziaWGCoreConfiguration {
        var interfaceValues: [String: String] = [:]
        var peerValues: [[String: String]] = []
        var currentPeerIndex: Int?
        var inInterface = false
        var sawSection = false

        for rawLine in text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            var line = String(rawLine)
            // Комментарии wg-quick. В значениях `<b 0x...>` символа '#' нет.
            if let comment = line.firstIndex(of: "#") {
                line = String(line[line.startIndex..<comment])
            }
            line = line.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }

            if line.hasPrefix("[") {
                let section = line.lowercased()
                sawSection = true
                switch section {
                case "[interface]":
                    inInterface = true
                    currentPeerIndex = nil
                case "[peer]":
                    inInterface = false
                    peerValues.append([:])
                    currentPeerIndex = peerValues.count - 1
                default:
                    throw WarpEngineError.configurationRejected("неизвестная секция \(line)")
                }
                continue
            }

            guard let separator = line.firstIndex(of: "=") else {
                throw WarpEngineError.configurationRejected("строка без '=': \(line)")
            }
            let key = String(line[line.startIndex..<separator])
                .trimmingCharacters(in: .whitespaces)
                .lowercased()
            let value = String(line[line.index(after: separator)...])
                .trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else {
                throw WarpEngineError.configurationRejected("пустой ключ в строке: \(line)")
            }

            if inInterface {
                try merge(key: key, value: value, into: &interfaceValues)
            } else if let index = currentPeerIndex {
                try merge(key: key, value: value, into: &peerValues[index])
            } else {
                throw WarpEngineError.configurationRejected("ключ \(key) вне секции")
            }
        }

        guard sawSection else {
            throw WarpEngineError.configurationRejected("конфиг без секций [Interface]/[Peer]")
        }

        let privateKey = interfaceValues["privatekey"]
        guard let privateKey, !privateKey.isEmpty else {
            throw WarpEngineError.configurationRejected("[Interface] без PrivateKey")
        }
        let addresses = try splitList(interfaceValues["address"], label: "Address")
        let dnsServers = try splitList(interfaceValues["dns"], label: "DNS", required: false)
        let mtu = try optionalUInt16(interfaceValues["mtu"], label: "MTU")
        let listenPort = try optionalUInt16(interfaceValues["listenport"], label: "ListenPort")

        var obfuscation = AmneziaWGCoreConfiguration.Obfuscation()
        obfuscation.jc = try optionalUInt16(interfaceValues["jc"], label: "Jc")
        obfuscation.jmin = try optionalUInt16(interfaceValues["jmin"], label: "Jmin")
        obfuscation.jmax = try optionalUInt16(interfaceValues["jmax"], label: "Jmax")
        obfuscation.s1 = try optionalUInt16(interfaceValues["s1"], label: "S1")
        obfuscation.s2 = try optionalUInt16(interfaceValues["s2"], label: "S2")
        obfuscation.s3 = try optionalUInt16(interfaceValues["s3"], label: "S3")
        obfuscation.s4 = try optionalUInt16(interfaceValues["s4"], label: "S4")
        obfuscation.h1 = interfaceValues["h1"]
        obfuscation.h2 = interfaceValues["h2"]
        obfuscation.h3 = interfaceValues["h3"]
        obfuscation.h4 = interfaceValues["h4"]
        obfuscation.i1 = interfaceValues["i1"]
        obfuscation.i2 = interfaceValues["i2"]
        obfuscation.i3 = interfaceValues["i3"]
        obfuscation.i4 = interfaceValues["i4"]
        obfuscation.i5 = interfaceValues["i5"]
        obfuscation.headerProtectionKeyHex = interfaceValues["headerprotectionkey"]
        obfuscation.contentPaddingAddition = interfaceValues["contentpaddingaddition"]
        obfuscation.rekeyAfterTime = interfaceValues["rekeyaftertime"]
        obfuscation.rekeyTimeout = interfaceValues["rekeytimeout"]
        obfuscation.rejectAfterTime = interfaceValues["rejectaftertime"]
        obfuscation.keepaliveTimeout = interfaceValues["keepalivetimeout"]
        obfuscation.maxHandshakeAttempts = interfaceValues["maxhandshakeattempts"]
        if let randomTrailers = interfaceValues["randomtrailers"] {
            obfuscation.randomTrailers = Self.boolValue(randomTrailers)
        }
        if let disableCookies = interfaceValues["disablecookies"] {
            obfuscation.disableCookies = Self.boolValue(disableCookies)
        }

        guard !peerValues.isEmpty else {
            throw WarpEngineError.configurationRejected("конфиг без секции [Peer]")
        }

        let peers: [AmneziaWGCoreConfiguration.Peer] = try peerValues.map { values in
            guard let publicKey = values["publickey"], !publicKey.isEmpty else {
                throw WarpEngineError.configurationRejected("[Peer] без PublicKey")
            }
            let allowedIPs = try splitList(values["allowedips"], label: "AllowedIPs")
            let endpoint: CandidateTarget?
            if let rawEndpoint = values["endpoint"], !rawEndpoint.isEmpty {
                guard let parsed = CandidateTarget(endpoint: rawEndpoint) else {
                    throw WarpEngineError.configurationRejected("невалидный Endpoint \(rawEndpoint)")
                }
                endpoint = parsed
            } else {
                endpoint = nil
            }
            let keepalive: UInt16?
            if let rawKeepalive = values["persistentkeepalive"], !rawKeepalive.isEmpty {
                let lowercased = rawKeepalive.lowercased()
                if lowercased == "off" || lowercased == "0" {
                    keepalive = nil
                } else {
                    keepalive = try optionalUInt16(rawKeepalive, label: "PersistentKeepalive")
                }
            } else {
                keepalive = nil
            }

            var peer = AmneziaWGCoreConfiguration.Peer(
                endpoint: endpoint,
                allowedIPs: allowedIPs,
                persistentKeepalive: keepalive
            )
            Self.assignKey(publicKey, hex: &peer.publicKeyHex, base64: &peer.publicKeyBase64)
            if let preshared = values["presharedkey"], !preshared.isEmpty {
                Self.assignKey(preshared, hex: &peer.presharedKeyHex, base64: &peer.presharedKeyBase64)
            }
            return peer
        }

        var configuration = AmneziaWGCoreConfiguration(addresses: addresses,
                                                       dnsServers: dnsServers,
                                                       mtu: mtu,
                                                       listenPort: listenPort,
                                                       obfuscation: obfuscation,
                                                       peers: peers)
        Self.assignKey(privateKey, hex: &configuration.privateKeyHex, base64: &configuration.privateKeyBase64)
        return configuration
    }

    // MARK: - Хелперы

    /// Ключи, которые wg-quick разрешает повторять (значения склеиваются).
    private static let repeatableKeys: Set<String> = ["address", "dns", "allowedips", "allowed_ip"]

    private static func merge(key: String, value: String, into attributes: inout [String: String]) throws {
        guard let previous = attributes[key] else {
            attributes[key] = value
            return
        }
        guard repeatableKeys.contains(key) else {
            throw WarpEngineError.configurationRejected("ключ \(key) повторяется в одной секции")
        }
        attributes[key] = previous + "," + value
    }

    private static func splitList(_ raw: String?, label: String, required: Bool = true) throws -> [String] {
        guard let raw else {
            if required {
                throw WarpEngineError.configurationRejected("не задано поле \(label)")
            }
            return []
        }
        let values = raw
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        if required, values.isEmpty {
            throw WarpEngineError.configurationRejected("пустое поле \(label)")
        }
        return values
    }

    private static func optionalUInt16(_ raw: String?, label: String) throws -> UInt16? {
        guard let raw, !raw.isEmpty else { return nil }
        guard let value = UInt16(raw) else {
            throw WarpEngineError.configurationRejected("\(label) вне диапазона UInt16: \(raw)")
        }
        return value
    }

    private static func boolValue(_ raw: String) -> Bool {
        switch raw.lowercased() {
        case "1", "true", "on", "yes": return true
        default: return false
        }
    }

    /// Ключ WireGuard приходит либо base64 (44 символа), либо hex (64 символа).
    private static func assignKey(_ raw: String, hex: inout String?, base64: inout String?) {
        if raw.count == 44, Data(base64Encoded: raw)?.count == 32 {
            base64 = raw
        } else if raw.count == 64, raw.allSatisfy({ $0.isHexDigit }) {
            hex = raw
        } else {
            // Неизвестный формат: отдаём как base64, пусть ядро отвергнет явно.
            base64 = raw
        }
    }
}

#else

// MARK: - Ядро не слинковано: честный unavailable

/// Фабрика-заглушка. Не «тихий success»: любая попытка запуска заканчивается
/// `WarpEngineError.engineUnavailable`, а отчёт валидатора — `.driverUnavailable`.
public final class WireGuardKitEngineFactory: WarpEngineFactory {
    public init() {}

    public var availability: WarpEngineAvailability {
        .unavailable(AmneziaWGCoreAdapter.unavailableReason)
    }

    public func makeEngine() throws -> any WarpEngine {
        throw WarpEngineError.engineUnavailable(AmneziaWGCoreAdapter.unavailableReason)
    }
}

/// Драйвер-заглушка: явная недоступность вместо имитации проверки.
public final class WireGuardKitTunnelTestDriver: TunnelTestDriving {
    public init() {}

    public var availability: TunnelTestDriverAvailability {
        .unavailable(AmneziaWGCoreAdapter.unavailableReason)
    }

    public func startTestSession(_ request: TestTunnelRequest) async throws -> any TunnelTestSession {
        throw WarpEngineError.engineUnavailable(AmneziaWGCoreAdapter.unavailableReason)
    }
}

#endif

// MARK: - Провайдер из Shared/WarpConfig

/// Конвертация `Shared/WarpConfig.swift` → нейтральная модель ядра.
///
/// Не зависит от WireGuardKit, поэтому доступна и в app, и в extension.
/// Endpoint всегда берётся из проверяемого кандидата (`target`), а не из
/// базового конфига: смысл тестового туннеля — идти именно на этот endpoint.
public struct WarpConfigCoreConfigurationProvider: AmneziaWGCoreConfigurationProviding {
    public init() {}

    public func coreConfiguration(for configuration: WarpConfig,
                                  target: CandidateTarget) throws -> AmneziaWGCoreConfiguration {
        // Повторная валидация AWG-параметров: ядро не должно получить мусор.
        let amnezia = try configuration.amneziaWG.validated()

        var obfuscation = AmneziaWGCoreConfiguration.Obfuscation()
        obfuscation.jc = try Self.uint16(amnezia.jc, label: "Jc")
        obfuscation.jmin = try Self.uint16(amnezia.jmin, label: "Jmin")
        obfuscation.jmax = try Self.uint16(amnezia.jmax, label: "Jmax")
        obfuscation.s1 = try Self.uint16(amnezia.s1, label: "S1")
        obfuscation.s2 = try Self.uint16(amnezia.s2, label: "S2")
        obfuscation.h1 = String(amnezia.h1)
        obfuscation.h2 = String(amnezia.h2)
        obfuscation.h3 = String(amnezia.h3)
        obfuscation.h4 = String(amnezia.h4)
        obfuscation.i1 = Self.specialJunkValue(amnezia.i1)

        var peer = AmneziaWGCoreConfiguration.Peer(endpoint: target,
                                                   allowedIPs: configuration.allowedIPs,
                                                   persistentKeepalive: configuration.persistentKeepalive)
        Self.assignKey(configuration.peerPublicKey,
                       hex: &peer.publicKeyHex,
                       base64: &peer.publicKeyBase64)

        var core = AmneziaWGCoreConfiguration(addresses: configuration.addresses,
                                              dnsServers: configuration.dns,
                                              mtu: configuration.mtu,
                                              obfuscation: obfuscation,
                                              peers: [peer])
        Self.assignKey(configuration.privateKey,
                       hex: &core.privateKeyHex,
                       base64: &core.privateKeyBase64)
        return core
    }

    /// `AmneziaWGParams` использует UInt32, а WireGuardKit — UInt16.
    /// Молча обрезать значение нельзя: это меняет конфиг ядра.
    static func uint16(_ value: UInt32, label: String) throws -> UInt16 {
        guard let converted = UInt16(exactly: value) else {
            throw WarpEngineError.configurationRejected("\(label)=\(value) вне диапазона UInt16")
        }
        return converted
    }

    /// `AmneziaWGParams.i1` — «голый» hex; UAPI ждёт спец-мусор с префиксом,
    /// т.е. `<b 0x…>`. Если значение уже в UAPI-формате, оно проходит как есть.
    static func specialJunkValue(_ rawHex: String) -> String {
        let trimmed = rawHex.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("<"), trimmed.hasSuffix(">") { return trimmed }
        return "<b 0x\(trimmed)>"
    }

    /// Ключ WireGuard: base64 (44 символа) или hex (64 символа).
    static func assignKey(_ raw: String, hex: inout String?, base64: inout String?) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.count == 44, Data(base64Encoded: trimmed)?.count == 32 {
            base64 = trimmed
        } else if trimmed.count == 64, trimmed.allSatisfy({ $0.isHexDigit }) {
            hex = trimmed
        } else {
            // Пусть ядро отвергнет явно, а не получит «тихо испорченный» ключ.
            base64 = trimmed
        }
    }
}

public extension WarpConfig {
    /// Нейтральная модель конфига ядра с endpoint проверяемого кандидата.
    func coreConfiguration(for target: CandidateTarget) throws -> AmneziaWGCoreConfiguration {
        try WarpConfigCoreConfigurationProvider().coreConfiguration(for: self, target: target)
    }
}
