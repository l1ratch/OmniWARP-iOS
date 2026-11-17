# OmniWARP-iOS — архитектура

## Цель

Полный on-device цикл, перенесённый с механики [Zapret-Manager/AmneziaWG](https://github.com/StressOzz/Zapret-Manager):

1. генерация параметров маскировки AWG;
2. регистрация WARP-аккаунта (ключи X25519 на устройстве);
3. разведка точек входа Cloudflare;
4. проверка кандидатов **через туннель** (handshake, RTT, колония, HTTPS);
5. сохранение трёх профилей и выбор лучшего живого;
6. раздельное туннелирование по спискам доменов.

## Компоненты

```
App/ (SwiftUI, iOS 17)
  ├─ TunnelManager        — NETunnelProviderManager lifecycle, generation, watchdog, IPC stats
  ├─ ScoutingViewModel    — 3 профиля, выбор fastest-alive
  ├─ AWGSettingsViewModel — AmneziaWGParams, пресет Zapret, генератор
  └─ DomainListsViewModel — пресеты itdoginfo + свои списки

Shared/ (app + extension)
  ├─ AmneziaWGParams.swift   — jc/jmin/jmax/s1/s2/h1..h4/i1, random(), zapretManager
  ├─ WarpConfig.swift        — WARP-конфиг + сериализация wg-quick/AWG
  ├─ WarpRegistrar.swift     — X25519 (CryptoKit), POST api/reg + fallback
  ├─ EndpointScout.swift     — HTTP trace-разведка 14 подсетей × порты
  ├─ DomainList.swift        — парсер .lst (itdoginfo), wildcard/suffix match
  └─ ConfigurationSnapshot.swift — versioned Codable → providerConfiguration

Tunnel/ (packet-tunnel extension)
  ├─ PacketTunnelProvider.swift   — NE entry, собственный парсер wg-quick/AWG,
  │                                  stats через WireGuardAdapter.getRuntimeConfiguration
  ├─ AmneziaWGCoreAdapter.swift   — boundary к WireGuardKit/amneziawg-go
  ├─ WarpEngine.swift             — протоколы движка, UAPI-парсер, handshake evidence
  ├─ CandidateValidator.swift     — корзины 1..5, 8 с handshake, 3 RTT-пробы, HTTPS
  ├─ DomainRouter.swift           — списки → резолв → exact /32,/128 RouteSnapshot
  ├─ DNSInterceptor.swift         — RFC1035 codec, upstream-резолв, A/AAAA
  └─ SNIExtractor.swift           — потоковый TLS ClientHello SNI + политика
```

## Data plane: почему WireGuardKit из amneziawg-apple

Используется [amneziawg-apple](https://github.com/amnezia-vpn/amneziawg-apple) @ `3bca528`:
SwiftPM-продукт называется `WireGuardKit`, но внутри `amneziawg-go/v3` — полная
userspace-реализация AWG (Jc/Jmin/Jmax/S1..S4/H1..H4/I1..I5 поддержаны в
`PacketTunnelSettingsGenerator.uapiConfiguration()`).

- Go-бридж собирается статически (`scripts/build-awg-core.sh` → `libwg-go.a`),
  без fork/exec — обязательное требование iOS.
- Handshake доказывается через UAPI `wgGetConfig` → `last_handshake_time_sec`.
- `TunnelConfiguration(fromWgQuickConfig:)` в SwiftPM-продукт **не входит**
  (internal, `Sources/Shared/Model`), поэтому в `PacketTunnelProvider` собственный
  строгий парсер wg-quick/AWG.

## Подбор: два независимых этапа

1. **EndpointScout (внешний).** HTTP `GET http://<ip>/cdn-cgi/trace` с
   `Host: trace.cloudflare.com`: RTT, `colo`, отбраковка RU-колоний
   (DME SVX LED KJA REN OVB KZN AER VVO). Метрики — про HTTP к IP, **не** про UDP-порт.
2. **CandidateValidator (через туннель).** Последовательно, top-N из scout:
   handshake ≤ 8 с → 3 RTT-пробы → colo изнутри → обязательный HTTPS.
   Корзины: новая colo+HTTPS → та же colo другой адрес → unknown → RU → HTTPS fail.
   ICMP-«пинги» заменены TCP/UDP-пробами (raw ICMP на iOS недоступен).

Параллельный перебор с несколькими туннелями невозможен: iOS не даёт два
`NEPacketTunnelProvider` одновременно. Тесты идут последовательно через
`TunnelTestDriving` с восстановлением исходной конфигурации.

## Split tunneling по доменам

Выбрана схема **real-IP + точные маршруты**, а не `/24` из WSBridge и не FakeIP:

```
списки доменов → DNS-резолв (A/AAAA) → exact /32 и /128
  → NE includedRoutes (динамически, через setTunnelNetworkSettings)
  → peer AllowedIPs = 0.0.0.0/0, ::/0 (захват ограничен маршрутами)
  → SNI-сверка для совпадения домена; mismatch/ECH/no-SNI → direct-политика
```

Почему не альтернативы:

- **`/24` CIDR (WSBridge)** — захватывает чужие сайты на shared CDN.
- **FakeIP** — удалённая сторона WARP не знает домен за `198.18.x.x`;
  пакет уйдёт в никуда. FakeIP требует локального netstack-прокси внутри
  extension (отдельный компонент `FakeIPPool` оставлен изолированным и
  **не подключён** к туннелю).

Обновление маршрутов — без рестарта туннеля; last-known-good списки при сбое
загрузки; ограниченная параллельность резолва.

## Ограничения iOS

- Неподписанный IPA — артефакт CI; app и `.appex` переподписываются при установке
  (GBox/SideStore/AltStore), NE entitlement и provisioning обязательны.
- Память extension ограничена (десятки МБ) — Go runtime в NE тестировать на
  реальном устройстве (jetsam).
- Фон — только пока активен NE; автопочинка — по событиям NE, не cron.
- Нет per-app маршрутизации; только `includedRoutes`/on-demand.
- App Groups не используются: настройки app → immutable snapshot в
  `providerConfiguration`; runtime health — provider messages.

## Источники

- Zapret-Manager: параметры AWG (`Zapret-Manager.sh:148-149`), подбор
  (`find_best_endpoint` L415-420; панель — `docs/autobypass.md` §5).
- WSBridge-iOS @ `5b1e50d`: NE skeleton, lifecycle, IPC; `/24`-split не переносился.
- amneziawg-apple @ `3bca528`, amneziawg-go @ `08fe3d3`.
