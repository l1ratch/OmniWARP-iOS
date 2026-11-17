import Foundation
import Observation

struct DomainListEntry: Identifiable, Codable, Equatable {
    var id: String { url }
    var title: String
    var url: String
    var isEnabled: Bool
    var isCustom: Bool
}

@MainActor
@Observable
final class DomainListsViewModel {
    var lists: [DomainListEntry]
    var newListTitle = ""
    var newListURL = ""
    var validationMessage: String?

    @ObservationIgnored
    private let defaults: UserDefaults
    @ObservationIgnored
    private let storageKey = "omniwarp.domain-lists.v1"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        if let data = defaults.data(forKey: "omniwarp.domain-lists.v1"),
           let saved = try? JSONDecoder().decode([DomainListEntry].self, from: data) {
            lists = Self.mergeSavedLists(saved)
        } else {
            lists = Self.presets
        }
        persist()
    }

    var enabledLists: [DomainListEntry] {
        lists.filter(\.isEnabled)
    }

    func addCustomList() {
        validationMessage = nil
        let rawURL = newListURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: rawURL),
              let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              url.host != nil else {
            validationMessage = "Введите полный HTTP или HTTPS URL списка доменов."
            return
        }
        guard lists.contains(where: { $0.url == url.absoluteString }) == false else {
            validationMessage = "Этот список уже добавлен."
            return
        }

        let title = newListTitle.trimmingCharacters(in: .whitespacesAndNewlines)
        lists.append(DomainListEntry(
            title: title.isEmpty ? (url.host ?? "Свой список") : title,
            url: url.absoluteString,
            isEnabled: true,
            isCustom: true
        ))
        newListTitle = ""
        newListURL = ""
        persist()
    }

    func removeCustomList(_ entry: DomainListEntry) {
        guard entry.isCustom else { return }
        lists.removeAll { $0.id == entry.id }
        persist()
    }

    func persist() {
        guard let data = try? JSONEncoder().encode(lists) else { return }
        defaults.set(data, forKey: storageKey)
    }

    private static let presets: [DomainListEntry] = [
        DomainListEntry(
            title: "itdoginfo — внутри РФ",
            url: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst",
            isEnabled: false,
            isCustom: false
        ),
        DomainListEntry(
            title: "itdoginfo — за пределами РФ",
            url: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-raw.lst",
            isEnabled: true,
            isCustom: false
        ),
        DomainListEntry(
            title: "itdoginfo — YouTube",
            url: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/youtube.lst",
            isEnabled: false,
            isCustom: false
        ),
        DomainListEntry(
            title: "itdoginfo — Discord",
            url: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/discord.lst",
            isEnabled: false,
            isCustom: false
        )
    ]

    /// Добавляет новые встроенные пресеты и заменяет старые URL `.txt`,
    /// которые upstream больше не раздаёт, на проверенные `.lst`.
    private static func mergeSavedLists(_ saved: [DomainListEntry]) -> [DomainListEntry] {
        let migrations = [
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-list.txt": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst",
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-list.txt": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-raw.lst",
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/youtube.txt": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/youtube.lst",
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/discord.txt": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/discord.lst"
        ]
        var result = saved.map { entry -> DomainListEntry in
            guard !entry.isCustom, let replacement = migrations[entry.url] else { return entry }
            var migrated = entry
            migrated.url = replacement
            if let preset = presets.first(where: { $0.url == replacement }) {
                migrated.title = preset.title
            }
            return migrated
        }
        var seen = Set<String>()
        result = result.filter { seen.insert($0.id).inserted }
        for preset in presets where result.contains(where: { $0.id == preset.id }) == false {
            result.append(preset)
        }
        return result
    }
}
