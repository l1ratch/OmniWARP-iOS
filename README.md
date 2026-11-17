# OmniWARP для iOS

iOS 17 / SwiftUI приложение и `NEPacketTunnelProvider`-расширение с полным
on-device циклом AmneziaWG/WARP: генерация параметров, регистрация ключей,
разведка endpoint'ов, последовательная проверка handshake/RTT/HTTPS и
раздельное туннелирование по спискам доменов. Data plane —
[AmneziaWG Apple / WireGuardKit](https://github.com/amnezia-vpn/amneziawg-apple).

Архитектура и перенос алгоритмов Zapret-Manager: [docs/ARCHITECTURE.ru.md](docs/ARCHITECTURE.ru.md).
CI на macOS собирает Go core, запускает XCTest и публикует unsigned IPA:
[.github/workflows/build.yml](.github/workflows/build.yml).

## Честный статус

- `project.yml` описывает приложение `OmniWARP`, расширение `OmniWARPTunnel`,
  test target `OmniWARPTests` и общий каталог `Shared`; App Groups не
  используются. DNS/SNI исходники дополнительно компилируются в test bundle,
  потому что `@testable import OmniWARP` не видит типы отдельного `.appex`.
- `ConfigurationSnapshot` — версионированный `Codable`. Для IPC используется
  JSON, дополнительно доступны binary/XML property-list helpers. Конкретные
  типы AWG/WARP в него не встроены: параметры и конфигурация передаются как
  `Data`.
- `PacketTunnelProvider` декодирует JSON из
  `providerConfiguration["configurationSnapshot"]`, запускает настоящий
  `WireGuardAdapter` при наличии `WireGuardKit`, обрабатывает остановку и
  `stats`-сообщения приложения. `AllowedIPs` в peer остаётся полным; split
  сужает только NE `includedRoutes`, поэтому шифрование AWG не зависит от
  DNS-разведки.
- `warpConfigData` на границе app/extension должен содержать **UTF-8 wg-quick
  текст** (`[Interface]` / `[Peer]`), включая AmneziaWG-поля `Jc`, `Jmin`,
  `Jmax`, `S1`…`S4`, `H1`…`H4`, `I1`…`I5`. Это не JSON конкретного
  `WarpConfig`. Собственный строгий парсер использует только публичный
  структурный API WireGuardKit, а не отсутствующий в SPM-продукте
  `TunnelConfiguration(fromWgQuickConfig:)`.
- Если модуль `WireGuardKit` недоступен, запуск завершается явной ошибкой
  `coreUnavailable`; успешная работа VPN не имитируется.
- Split tunneling реализован в жизненном цикле провайдера: при включённом
  флаге провайдер заранее загружает списки, резолвит точные A/AAAA маршруты
  через `SplitTunnelController`, применяет их к NE network settings после
  старта AWG и периодически обновляет по TTL. При выключенном флаге остаётся
  обычный полный туннель.

## Требования

Сборка выполняется на macOS:

- Xcode с iOS 17 SDK;
- [XcodeGen](https://github.com/yonaskolb/XcodeGen);
- Go, `make`, `rsync`, `clang`, `lipo` для статической Go-библиотеки AWG.

Например: `brew install xcodegen go`.

## Генерация и сборка

Проект `OmniWARP.xcodeproj` генерируемый и не хранится в git.

### 1. Сгенерировать проект и получить SPM checkout

```sh
xcodegen generate --spec project.yml
xcodebuild \
  -project OmniWARP.xcodeproj \
  -scheme OmniWARP \
  -derivedDataPath "$PWD/DerivedData" \
  -resolvePackageDependencies
```

Зависимость закреплена на revision
`3bca528aca844bbe6b665d8ab5c6724cd261fd54`.

### 2. Отдельно собрать Go core

SPM **не собирает** `libwg-go.a`: upstream `WireGuardKitGo` рассчитан на вызов
своего `Sources/WireGuardKitGo/Makefile`. Поэтому перед обычной сборкой нужен
второй этап:

```sh
# Для физического устройства (arm64):
bash scripts/build-awg-core.sh "$PWD/DerivedData" Debug iphoneos

# Либо для симулятора (x86_64 + arm64):
bash scripts/build-awg-core.sh "$PWD/DerivedData" Debug iphonesimulator
```

Скрипт вызывает Makefile в resolved checkout и создаёт
`Sources/WireGuardKitGo/out/libwg-go.a` — именно тот путь, который ожидает
`Package.swift`. Для смены device/simulator скрипт запускают заново, потому что
обе конфигурации используют одно имя выходной библиотеки.

### 3. Собрать приложение и расширение

Для simulator-only проверки без подписи:

```sh
xcodebuild \
  -project OmniWARP.xcodeproj \
  -scheme OmniWARP \
  -configuration Debug \
  -destination 'platform=iOS Simulator,name=iPhone 15' \
  -derivedDataPath "$PWD/DerivedData" \
  CODE_SIGNING_ALLOWED=NO \
  build
```

Для устройства (предварительно соберите core с `iphoneos`):

```sh
xcodebuild \
  -project OmniWARP.xcodeproj \
  -scheme OmniWARP \
  -configuration Debug \
  -destination 'generic/platform=iOS' \
  -derivedDataPath "$PWD/DerivedData" \
  DEVELOPMENT_TEAM='<TEAM_ID>' \
  CODE_SIGN_STYLE=Automatic \
  build
```

Вместо `<TEAM_ID>` нужен реальный Apple Developer Team ID. Имя simulator
можно заменить на установленное окружение.

## Тесты

После сборки simulator-варианта Go core:

```sh
xcodebuild \
  -project OmniWARP.xcodeproj \
  -scheme OmniWARP \
  -destination 'platform=iOS Simulator,name=iPhone 15' \
  -derivedDataPath "$PWD/DerivedData" \
  CODE_SIGNING_ALLOWED=NO \
  test
```

`OmniWARPTests` использует host application `OmniWARP`; чистые DNS/SNI/Domain
Router исходники включены в test bundle напрямую, без `PacketTunnelProvider` и
других NE-only файлов.

## Версионирование и публикация IPA

Используется формат **X.Y.N**, как в WSBridge:

- `OMW_VERSION = X.Y` в `project.yml` меняется только вручную перед стабильным
  релизом;
- `OMW_BUILD = N` — номер preview-сборки. После успешной публикации CI коммитит
  `N+1` в `main` с `[skip ci]`;
- каждый push в `main` запускает `Build Preview IPA`: тесты → сборка AWG core →
  unsigned IPA → обновление prerelease `preview` и AltStore/GBox-источника в
  `gh-pages`;
- стабильный релиз создаётся только вручную тегом `vX.Y.N`, который должен
  совпадать с `project.yml`. Для него используется `Release (Tag v*)`.

Preview-манифест после первой публикации:
`https://l1ratch.github.io/OmniWARP-iOS/source.json`.
IPA неподписанный: это артефакт сборки, а не обход требований подписи iOS.

## Подпись Network Extension

`CODE_SIGNING_ALLOWED=NO` пригоден только для локальной compile-check сборки.
Он **не отменяет** требования подписи на устройстве и не заменяет re-signing.

Для запуска на iOS-устройстве необходимо:

1. Зарегистрировать App IDs `com.omniwarp.OmniWARP` и
   `com.omniwarp.OmniWARP.tunnel` в одной команде разработчика.
2. Включить Network Extensions capability с `packet-tunnel-provider` для
   extension и `allow-vpn` для приложения; provisioning profiles должны
   содержать соответствующие entitlements.
3. Подписать extension и вложить подписанный `.appex` в подписанное приложение.
   После любого ручного re-signing приложения вложенное расширение также нужно
   корректно переподписать в правильном порядке (сначала `.appex`, затем app).
4. Установить обновлённые profiles в Xcode и выбрать одинаковый Team у обоих
   targets.

Ограничения бесплатной учётной записи и managed enterprise profiles могут
отличаться; рабочая разработка Network Extension обычно требует соответствующих
прав в Apple Developer Program.

## IPC

- Ключ snapshot: `configurationSnapshot`; значение: `Data` от `JSONEncoder`.
- Запрос статистики: JSON `{"command":"stats","request":"stats"}` (достаточно
  любого из двух ключей со значением `stats`).
- Успешный ответ: `ok`, `receivedBytes`, `transmittedBytes` и опциональный Unix
  timestamp `lastHandshake`.
- Ошибка: `{"ok":false,"error":"..."}`.

## Минимальный fixture для проверки парсера

Следующий текст можно положить в `warpConfigData` для smoke-проверки разбора
полей (ключи нулевые/тестовые, endpoint из TEST-NET-1 — это **не рабочий VPN**):

```ini
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32
DNS = 1.1.1.1
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <b 0x01020304>

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.1:4500
PersistentKeepalive = 25
```

`I1` должен оставаться строкой `<b 0x01020304>` в `specialJunk1`; её нельзя
преобразовывать в обычный hex без управляющего `<b ...>`-формата AmneziaWG.
Приватные ключи и итоговый wg-quick текст не выводятся в лог.
