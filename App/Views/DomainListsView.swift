import SwiftUI

struct DomainListsView: View {
    @Bindable var model: DomainListsViewModel

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                ScreenHeading(
                    title: "Домены",
                    subtitle: "Включённые списки попадут в следующий снимок конфигурации."
                )
                .padding(.horizontal)
                .padding(.top)

                if let validationMessage = model.validationMessage {
                    NoticeView(title: "URL не добавлен", message: validationMessage, tone: .error)
                        .padding(.horizontal)
                }

                List {
                    Section {
                        ForEach($model.lists) { $entry in
                            if entry.isCustom == false {
                                row(for: $entry)
                            }
                        }
                    } header: {
                        Text("Пресеты itdoginfo")
                    }

                    Section {
                        ForEach($model.lists) { $entry in
                            if entry.isCustom {
                                row(for: $entry)
                                    .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                        Button("Удалить", role: .destructive) {
                                            model.removeCustomList(entry)
                                        }
                                    }
                            }
                        }

                        TextField("Название (необязательно)", text: $model.newListTitle)
                        TextField("https://example.com/domains.txt", text: $model.newListURL)
                            .keyboardType(.URL)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button("Добавить список") {
                            model.addCustomList()
                        }
                        .disabled(model.newListURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    } header: {
                        Text("Свои URL")
                    } footer: {
                        Text("Поддерживаются HTTP и HTTPS. Проверка содержимого выполняется при обновлении конфигурации туннеля.")
                    }
                }
                .listStyle(.insetGrouped)
                .scrollContentBackground(.hidden)
            }
            .background(Color(.systemGroupedBackground))
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func row(for entry: Binding<DomainListEntry>) -> some View {
        Toggle(isOn: entry.isEnabled) {
            VStack(alignment: .leading, spacing: 4) {
                Text(entry.wrappedValue.title)
                Text(entry.wrappedValue.url)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .textSelection(.enabled)
            }
        }
        .onChange(of: entry.wrappedValue.isEnabled) { _, _ in
            model.persist()
        }
    }
}
