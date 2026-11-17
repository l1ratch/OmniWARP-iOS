import SwiftUI

struct AWGSettingsView: View {
    @Bindable var model: AWGSettingsViewModel

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ScreenHeading(
                        title: "AWG",
                        subtitle: "Параметры обфускации AmneziaWG. Изменения применяются при следующем подключении."
                    )
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 12, leading: 0, bottom: 8, trailing: 0))

                    HStack(spacing: 12) {
                        Button {
                            model.generateRandomProfile()
                        } label: {
                            Label("Случайный", systemImage: "dice")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)

                        Button {
                            model.applyZapretPreset()
                        } label: {
                            Label("Zapret", systemImage: "shippingbox")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                    }
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
                }

                if let message = model.message {
                    Section {
                        NoticeView(title: "Профиль применён", message: message, tone: .success)
                    }
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                }
                if let validationError = model.validationError {
                    Section {
                        NoticeView(title: "Проверьте параметры", message: validationError, tone: .error)
                    }
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                }

                Section("Мусорные пакеты") {
                    LabeledNumberField(title: "Jc — количество", value: $model.jc)
                    LabeledNumberField(title: "Jmin — минимальный размер", value: $model.jmin)
                    LabeledNumberField(title: "Jmax — максимальный размер", value: $model.jmax)
                }

                Section("Смещения") {
                    LabeledNumberField(title: "S1", value: $model.s1)
                    LabeledNumberField(title: "S2", value: $model.s2)
                }

                Section {
                    LabeledNumberField(title: "H1", value: $model.h1)
                    LabeledNumberField(title: "H2", value: $model.h2)
                    LabeledNumberField(title: "H3", value: $model.h3)
                    LabeledNumberField(title: "H4", value: $model.h4)
                } header: {
                    Text("Магические заголовки")
                } footer: {
                    Text("H1–H4 должны различаться. Некорректный профиль не будет выдан за рабочий: ошибка валидатора отобразится отдельно.")
                }

                Section {
                    TextField("Hex-пакет без <b 0x…>", text: $model.i1, axis: .vertical)
                        .font(.caption.monospaced())
                        .lineLimit(3...8)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onChange(of: model.i1) { _, _ in model.validateAndPersist() }
                } header: {
                    Text("I1 — initiation-пакет")
                } footer: {
                    Text("От 10 до 1200 байт в hex. В wg-quick префикс <b 0x…> добавляется автоматически.")
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Color(.systemGroupedBackground))
            .navigationBarTitleDisplayMode(.inline)
            .onSubmit { model.validateAndPersist() }
        }
    }
}
