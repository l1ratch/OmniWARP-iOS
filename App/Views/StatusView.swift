import NetworkExtension
import SwiftUI

struct StatusView: View {
    @ObservedObject var tunnel: TunnelManager
    @Bindable var registration: WarpRegistrationViewModel
    @Bindable var autoSetup: AutoSetupViewModel
    let configuredEndpoint: String
    let configuredColo: String?
    let isScouting: Bool
    let makeSnapshot: () throws -> Data
    let registerWarp: () async -> Void
    let startAutoSetup: () -> Void

    @State private var configurationError: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    ScreenHeading(
                        title: "Статус",
                        subtitle: "Управляйте защищённым соединением и проверяйте ответ ядра."
                    )

                    connectionControl
                    automaticSetup
                    warpRegistration

                    VStack(spacing: 12) {
                        DetailRow(
                            title: "Endpoint",
                            value: tunnel.currentEndpoint ?? configuredEndpoint,
                            monospaced: true
                        )
                        DetailRow(
                            title: "Colo",
                            value: tunnel.currentColo ?? configuredColo ?? "Не определён"
                        )
                        Divider()
                        coreState
                    }
                    .padding(.horizontal, 4)

                    if tunnel.status == .connected {
                        statistics
                    }

                    if let configurationError {
                        NoticeView(title: "Проверьте конфигурацию", message: configurationError, tone: .error)
                    }
                    if let lastError = tunnel.lastError, lastError != configurationError {
                        NoticeView(title: "Состояние подключения", message: lastError, tone: .warning)
                    }
                }
                .padding()
            }
            .background(Color(.systemGroupedBackground))
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var connectionControl: some View {
        VStack(spacing: 16) {
            Button(action: toggleConnection) {
                ZStack {
                    Circle()
                        .fill(buttonColor.opacity(0.10))
                    Circle()
                        .stroke(buttonColor.opacity(0.28), lineWidth: 1)
                        .padding(10)
                    if tunnel.isBusy {
                        ProgressView()
                            .controlSize(.large)
                            .tint(buttonColor)
                    } else {
                        Image(systemName: "power")
                            .font(.system(size: 42, weight: .medium))
                            .foregroundStyle(buttonColor)
                    }
                }
                .frame(width: 156, height: 156)
                .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .disabled(isScouting || autoSetup.isRunning || tunnel.isTestingCandidates || registration.isRegistering || tunnel.status == .disconnecting)
            .accessibilityLabel(tunnel.isTunnelActive ? "Отключить туннель" : "Подключить туннель")
            .accessibilityHint("Действие меняет состояние системного VPN")

            VStack(spacing: 5) {
                Text(tunnel.statusTitle)
                    .font(.title3.weight(.semibold))
                Text(tunnel.isTunnelActive ? "Нажмите, чтобы отключить" : "Нажмите, чтобы подключить")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }

    private var automaticSetup: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Автоматическая настройка", systemImage: "wand.and.stars")
                .font(.subheadline.weight(.semibold))
            Text("Получит WARP-ключи, проверит три AWG-профиля на лучших точках входа и подключит лучший рабочий конфиг.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Button(action: startAutoSetup) {
                HStack {
                    if autoSetup.isRunning {
                        ProgressView()
                    } else {
                        Image(systemName: "bolt.fill")
                    }
                    Text(autoSetup.isRunning ? "Подбираем конфигурацию…" : "Собрать и подключить")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(autoSetup.isRunning || tunnel.isTunnelActive || isScouting || tunnel.isTestingCandidates || registration.isRegistering)

            if autoSetup.isRunning {
                Button("Отменить", role: .cancel, action: autoSetup.cancel)
                    .frame(maxWidth: .infinity, alignment: .center)
            }

            Text(autoSetup.phaseMessage)
                .font(.caption)
                .foregroundStyle(.secondary)
            if autoSetup.isRunning || autoSetup.progress > 0 {
                ProgressView(value: autoSetup.progress)
            }
            if let statusMessage = autoSetup.statusMessage {
                NoticeView(title: "Автоматическая настройка", message: statusMessage, tone: .success)
            }
            if let errorMessage = autoSetup.errorMessage {
                NoticeView(title: "Подбор не завершён", message: errorMessage, tone: .error)
            }
        }
        .padding(14)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    private var warpRegistration: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Ключи WARP", systemImage: "key")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text(registration.isReady ? "Получены" : "Нужна регистрация")
                    .font(.caption)
                    .foregroundStyle(registration.isReady ? Color.green : Color.orange)
            }

            if let config = registration.config {
                Text("Адресов интерфейса: \(config.addresses.count). Приватный ключ хранится в Keychain и не показывается.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("Перед подключением получите новую пару ключей и адреса WARP.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Button {
                Task { await registerWarp() }
            } label: {
                HStack {
                    if registration.isRegistering {
                        ProgressView()
                    } else {
                        Image(systemName: "person.badge.key")
                    }
                    Text(registration.isReady ? "Обновить ключи" : "Получить ключи")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .disabled(registration.isRegistering || autoSetup.isRunning || tunnel.isTunnelActive || isScouting || tunnel.isTestingCandidates)

            if let statusMessage = registration.statusMessage {
                NoticeView(title: "Регистрация WARP", message: statusMessage, tone: .success)
            }
            if let lastError = registration.lastError {
                NoticeView(title: "Регистрация не выполнена", message: lastError, tone: .error)
            }
        }
        .padding(14)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    @ViewBuilder
    private var coreState: some View {
        VStack(spacing: 10) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: coreIcon)
                    .foregroundStyle(coreColor)
                VStack(alignment: .leading, spacing: 3) {
                    Text(tunnel.coreStatusTitle)
                        .font(.subheadline.weight(.medium))
                    if let detail = tunnel.coreStatusDetail {
                        Text(detail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
                Spacer()
            }

            if tunnel.status == .connected {
                Button {
                    Task { await tunnel.refreshStats() }
                } label: {
                    Label("Проверить ядро", systemImage: "arrow.clockwise")
                        .font(.subheadline.weight(.medium))
                }
                .frame(maxWidth: .infinity, alignment: .trailing)
            }
        }
    }

    private var statistics: some View {
        VStack(spacing: 12) {
            HStack {
                Label("Принято", systemImage: "arrow.down")
                    .foregroundStyle(.secondary)
                Spacer()
                Text(tunnel.trafficStats?.receivedBytes.formattedTraffic ?? "—")
                    .monospaced()
            }
            HStack {
                Label("Отправлено", systemImage: "arrow.up")
                    .foregroundStyle(.secondary)
                Spacer()
                Text(tunnel.trafficStats?.transmittedBytes.formattedTraffic ?? "—")
                    .monospaced()
            }
            Divider()
            DetailRow(
                title: "Последний handshake",
                value: tunnel.trafficStats?.lastHandshake?.formattedHandshake ?? "Не подтверждён"
            )
        }
        .font(.subheadline)
        .padding(14)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    private var buttonColor: Color {
        switch tunnel.status {
        case .connected: return .green
        case .connecting, .reasserting, .disconnecting: return .orange
        default: return .accentColor
        }
    }

    private var coreColor: Color {
        switch tunnel.coreHealth {
        case .unknown: return .secondary
        case .checking: return .orange
        case .available: return .green
        case .unavailable: return .red
        }
    }

    private var coreIcon: String {
        switch tunnel.coreHealth {
        case .unknown: return "questionmark.circle"
        case .checking: return "dot.radiowaves.left.and.right"
        case .available: return "checkmark.circle"
        case .unavailable: return "exclamationmark.triangle"
        }
    }

    private func toggleConnection() {
        configurationError = nil
        do {
            let snapshot: Data
            if tunnel.isTunnelActive {
                snapshot = Data()
            } else {
                snapshot = try makeSnapshot()
            }
            Task {
                await tunnel.toggle(
                    snapshotJSON: snapshot,
                    endpoint: configuredEndpoint,
                    colo: configuredColo
                )
            }
        } catch {
            configurationError = error.localizedDescription
        }
    }
}
