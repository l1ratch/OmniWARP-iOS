import SwiftUI

struct ScoutingView: View {
    @Bindable var model: ScoutingViewModel

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                ScreenHeading(
                    title: "Подбор",
                    subtitle: "Проверяйте endpoint по RTT, потерям и доступности HTTPS."
                )

                controls
                scoutingState
                validationNotices
                profiles
                candidateTable
            }
            .padding()
            .background(Color(.systemGroupedBackground))
            .navigationBarTitleDisplayMode(.inline)
            .onChange(of: model.selectedCandidateID) { _, _ in
                model.candidateSelectionChanged()
            }
        }
    }

    private var controls: some View {
        HStack(spacing: 12) {
            Button {
                model.start()
            } label: {
                Label("Подобрать", systemImage: "scope")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.isRunning)

            if model.isRunning {
                Button("Отмена", role: .cancel) {
                    model.cancelScouting()
                }
                .buttonStyle(.bordered)
            } else {
                Button {
                    model.selectFastestAlive()
                } label: {
                    Label("Самый быстрый живой", systemImage: "bolt")
                }
                .buttonStyle(.bordered)
                .disabled(model.candidates.contains(where: { $0.isUsable }) == false)
            }
        }
    }

    @ViewBuilder
    private var scoutingState: some View {
        switch model.phase {
        case .idle:
            if model.candidates.isEmpty {
                NoticeView(
                    title: "Проверка ещё не запускалась",
                    message: "Нажмите «Подобрать». Результаты появятся только после реальных сетевых проверок."
                )
            }
        case .running:
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(model.progress < 0.4 ? "HTTP-разведка endpoint’ов" : "Handshake и HTTPS: top-8")
                        .font(.subheadline.weight(.medium))
                    Spacer()
                    Text(model.progress.formatted(.percent.precision(.fractionLength(0))))
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                ProgressView(value: model.progress)
            }
        case .completed:
            NoticeView(
                title: "Проверка завершена",
                message: "Найдено кандидатов: \(model.candidates.count). Доступные HTTPS: \(model.candidates.filter(\.isUsable).count).",
                tone: model.candidates.contains(where: { $0.isUsable }) ? .success : .warning
            )
        case .failed(let message):
            NoticeView(title: "Подбор не завершён", message: message, tone: .error)
        }
    }

    @ViewBuilder
    private var validationNotices: some View {
        if let summary = model.validationSummary {
            NoticeView(title: "CandidateValidator", message: summary, tone: .neutral)
        }
        if let warning = model.validationWarning {
            NoticeView(title: "Ограничение проверки", message: warning, tone: .warning)
        }
    }

    private var profiles: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("Сохранённый профиль", selection: $model.activeProfileIndex) {
                ForEach(model.profiles) { profile in
                    Text(profile.name).tag(profile.id)
                }
            }
            .pickerStyle(.segmented)

            HStack {
                if let savedAt = model.activeProfile.savedAt {
                    Text("Сохранён \(savedAt.formatted(date: .abbreviated, time: .shortened))")
                } else {
                    Text("Профиль пока пуст")
                }
                Spacer()
                if let selected = model.selectedCandidate {
                    Text(selected.endpoint)
                        .textSelection(.enabled)
                        .lineLimit(1)
                } else {
                    Text("Endpoint не выбран")
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    private var candidateTable: some View {
        Table(model.candidates, selection: $model.selectedCandidateID) {
            TableColumn("Endpoint") { candidate in
                Text(candidate.endpoint)
                    .font(.caption.monospaced())
                    .lineLimit(1)
            }
            TableColumn("Colo") { candidate in
                Text(candidate.colo)
            }
            TableColumn("RTT") { candidate in
                Text(candidate.rttMilliseconds.map { "\(Int($0.rounded())) мс" } ?? "—")
                    .monospacedDigit()
            }
            TableColumn("Потери") { candidate in
                Text("\(Int(candidate.lossPercentage.rounded()))%")
                    .monospacedDigit()
            }
            TableColumn("HTTPS") { candidate in
                Image(systemName: candidate.httpsReachable ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundStyle(candidate.httpsReachable ? Color.green : Color.red)
                    .accessibilityLabel(candidate.httpsReachable ? "HTTPS доступен" : "HTTPS недоступен")
            }
            TableColumn("Итог") { candidate in
                Text(candidate.validationTitle ?? "Только scout")
                    .font(.caption)
                    .lineLimit(2)
            }
        }
        .frame(minHeight: 220)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay {
            if model.candidates.isEmpty && !model.isRunning {
                ContentUnavailableView(
                    "Нет кандидатов",
                    systemImage: "network",
                    description: Text("Запустите подбор или выберите другой сохранённый профиль.")
                )
                .background(Color(.secondarySystemGroupedBackground))
            }
        }
    }
}
