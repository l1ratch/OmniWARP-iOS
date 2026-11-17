import Foundation
import Observation

enum AWGInputError: LocalizedError {
    case notANumber(String)

    var errorDescription: String? {
        switch self {
        case .notANumber(let field):
            return "Поле \(field) должно содержать целое неотрицательное число до \(UInt32.max)."
        }
    }
}

@MainActor
@Observable
final class AWGSettingsViewModel {
    var jc = "3"
    var jmin = "10"
    var jmax = "50"
    var s1 = "0"
    var s2 = "0"
    var h1 = "1"
    var h2 = "2"
    var h3 = "3"
    var h4 = "4"
    var i1 = ""
    var message: String?
    var validationError: String?

    @ObservationIgnored
    private let defaults: UserDefaults
    @ObservationIgnored
    private let storageKey = "omniwarp.awg.params.v2"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        if let data = defaults.data(forKey: "omniwarp.awg.params.v2"),
           let values = try? JSONDecoder().decode(AmneziaWGParams.self, from: data) {
            apply(values)
        } else {
            apply(.zapretPreset)
        }
    }

    func generateRandomProfile() {
        apply(AmneziaWGParams.random())
        validateAndPersist()
        message = "Создан случайный профиль AmneziaWG."
    }

    func applyZapretPreset() {
        apply(.zapretPreset)
        validateAndPersist()
        message = "Применён пресет Zapret. Он не гарантирует прохождение проверки сети."
    }

    func apply(_ values: AmneziaWGParams) {
        jc = String(values.jc)
        jmin = String(values.jmin)
        jmax = String(values.jmax)
        s1 = String(values.s1)
        s2 = String(values.s2)
        h1 = String(values.h1)
        h2 = String(values.h2)
        h3 = String(values.h3)
        h4 = String(values.h4)
        i1 = values.i1
        validationError = nil
    }

    @discardableResult
    func validatedValues() throws -> AmneziaWGParams {
        let values = try AmneziaWGParams(
            jc: number(jc, field: "Jc"),
            jmin: number(jmin, field: "Jmin"),
            jmax: number(jmax, field: "Jmax"),
            s1: number(s1, field: "S1"),
            s2: number(s2, field: "S2"),
            h1: number(h1, field: "H1"),
            h2: number(h2, field: "H2"),
            h3: number(h3, field: "H3"),
            h4: number(h4, field: "H4"),
            i1: i1.trimmingCharacters(in: .whitespacesAndNewlines)
        ).validated()
        validationError = nil
        persist(values)
        return values
    }

    func validateAndPersist() {
        do {
            try validatedValues()
        } catch {
            validationError = error.localizedDescription
        }
    }

    private func number(_ string: String, field: String) throws -> UInt32 {
        guard let value = UInt32(string.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw AWGInputError.notANumber(field)
        }
        return value
    }

    private func persist(_ values: AmneziaWGParams) {
        guard let data = try? JSONEncoder().encode(values) else { return }
        defaults.set(data, forKey: storageKey)
    }
}
