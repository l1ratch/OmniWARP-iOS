import Foundation
import Observation

struct ScoutingCandidate: Identifiable, Codable, Equatable {
    let id: String
    var endpoint: String
    var colo: String
    var rttMilliseconds: Double?
    var lossPercentage: Double
    var httpsStatus: Int?
    var isAlive: Bool
    var source: EndpointSource
    var bucketRawValue: Int?
    var validationTitle: String?

    init(_ candidate: EndpointCandidate) {
        id = candidate.id
        endpoint = candidate.id
        colo = candidate.colo ?? "—"
        rttMilliseconds = candidate.rttMilliseconds
        lossPercentage = candidate.lossPercentage ?? 100
        httpsStatus = candidate.httpsStatus
        source = candidate.source
        isAlive = candidate.rttMilliseconds != nil && (candidate.lossPercentage ?? 100) < 100
        bucketRawValue = nil
        validationTitle = nil
    }

    var httpsReachable: Bool {
        guard let httpsStatus else { return false }
        return (200..<300).contains(httpsStatus)
    }

    var bucket: CandidateBucket? {
        bucketRawValue.flatMap(CandidateBucket.init(rawValue:))
    }

    var isUsable: Bool {
        if validationTitle != nil {
            return bucket?.isConfirmed == true && isAlive && httpsReachable && lossPercentage < 100
        }
        return isAlive && httpsReachable && lossPercentage < 100
    }

    var endpointCandidate: EndpointCandidate {
        let separator = endpoint.lastIndex(of: ":")
        let host = separator.map { String(endpoint[..<$0]) } ?? endpoint
        let port = separator.flatMap { UInt16(endpoint[endpoint.index(after: $0)...]) } ?? 2408
        return EndpointCandidate(
            ip: host,
            port: port,
            colo: colo == "—" ? nil : colo,
            rttMilliseconds: rttMilliseconds,
            lossPercentage: lossPercentage,
            httpsStatus: httpsStatus,
            source: source
        )
    }

    mutating func apply(_ validation: CandidateValidation) {
        colo = validation.colo ?? colo
        rttMilliseconds = validation.medianRTTMs ?? validation.rankedRTTMs
        lossPercentage = validation.lossPercentage
        httpsStatus = validation.https?.httpStatus
        isAlive = validation.isAlive
        bucketRawValue = validation.bucket?.rawValue
        validationTitle = validation.status.title
    }
}

struct ScoutingProfile: Identifiable, Codable, Equatable {
    let id: Int
    var name: String
    var savedAt: Date?
    var candidates: [ScoutingCandidate]
    var selectedCandidateID: String?

    var selectedCandidate: ScoutingCandidate? {
        candidates.first { $0.id == selectedCandidateID }
    }
}

struct ScoutingValidationResult {
    var candidates: [ScoutingCandidate]
    var preferredCandidateID: String?
    var warning: String?
    var summary: String?
}

@MainActor
@Observable
final class ScoutingViewModel {
    enum Phase: Equatable {
        case idle
        case running
        case completed
        case failed(String)
    }

    var phase: Phase = .idle
    var progress: Double = 0
    var candidates: [ScoutingCandidate] = []
    var profiles: [ScoutingProfile]
    var activeProfileIndex = 0 {
        didSet { loadActiveProfile() }
    }
    var selectedCandidateID: String?
    var validationWarning: String?
    var validationSummary: String?

    @ObservationIgnored
    var scoutingOperation: ((@escaping (Double) -> Void) async throws -> [ScoutingCandidate])?
    @ObservationIgnored
    var validationOperation: (([ScoutingCandidate], @escaping (Double) -> Void) async throws -> ScoutingValidationResult)?

    @ObservationIgnored
    private let defaults: UserDefaults
    @ObservationIgnored
    private let storageKey = "omniwarp.scouting.profiles.v3"
    @ObservationIgnored
    private var runTask: Task<Void, Never>?

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let empty = (0..<3).map {
            ScoutingProfile(id: $0, name: "Профиль \($0 + 1)", savedAt: nil, candidates: [], selectedCandidateID: nil)
        }
        if let data = defaults.data(forKey: "omniwarp.scouting.profiles.v3"),
           let saved = try? JSONDecoder().decode([ScoutingProfile].self, from: data),
           saved.count == 3 {
            profiles = saved
        } else {
            profiles = empty
        }
        selectedCandidateID = profiles[0].selectedCandidateID
        candidates = profiles[0].candidates
    }

    var activeProfile: ScoutingProfile {
        profiles[activeProfileIndex]
    }

    var selectedCandidate: ScoutingCandidate? {
        candidates.first { $0.id == selectedCandidateID }
    }

    var isRunning: Bool { phase == .running }

    func start() {
        guard runTask == nil else { return }
        runTask = Task { [weak self] in
            guard let self else { return }
            await self.startScouting()
            self.runTask = nil
        }
    }

    func cancelScouting() {
        runTask?.cancel()
    }

    func startScouting() async {
        guard !isRunning else { return }
        guard let scoutingOperation else {
            phase = .failed("Модуль EndpointScout пока недоступен. Проверьте сборку приложения.")
            return
        }

        phase = .running
        progress = 0
        validationWarning = nil
        validationSummary = nil
        do {
            var result = try await scoutingOperation { [weak self] value in
                Task { @MainActor in
                    self?.progress = min(max(value * 0.4, 0), 0.4)
                }
            }
            try Task.checkCancellation()
            var preferredCandidateID: String?

            if let validationOperation {
                do {
                    let validation = try await validationOperation(result) { [weak self] value in
                        Task { @MainActor in
                            self?.progress = 0.4 + min(max(value, 0), 1) * 0.6
                        }
                    }
                    result = validation.candidates
                    preferredCandidateID = validation.preferredCandidateID
                    validationWarning = validation.warning
                    validationSummary = validation.summary
                } catch is CancellationError {
                    throw CancellationError()
                } catch {
                    validationWarning = "Полная проверка не завершена: \(error.localizedDescription). Показаны только результаты HTTP scout."
                }
            } else {
                validationWarning = "CandidateValidator недоступен. Показаны только HTTP-метрики scout, handshake не подтверждён."
            }

            try Task.checkCancellation()
            candidates = result
            if let preferredCandidateID,
               let preferred = result.first(where: { $0.id == preferredCandidateID && $0.isUsable }) {
                selectedCandidateID = preferred.id
            } else {
                selectedCandidateID = bestCandidate(in: result)?.id
            }
            phase = .completed
            progress = 1
            saveCurrentToActiveProfile()
        } catch is CancellationError {
            phase = .idle
            progress = 0
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    func selectFastestAlive() {
        selectedCandidateID = bestCandidate(in: candidates)?.id
        saveCurrentToActiveProfile()
    }

    func saveCurrentToActiveProfile() {
        profiles[activeProfileIndex].candidates = candidates
        profiles[activeProfileIndex].selectedCandidateID = selectedCandidateID
        profiles[activeProfileIndex].savedAt = candidates.isEmpty ? nil : Date()
        persistProfiles()
    }

    func candidateSelectionChanged() {
        if let selectedCandidate, !selectedCandidate.isUsable {
            selectedCandidateID = nil
        }
        profiles[activeProfileIndex].selectedCandidateID = selectedCandidateID
        persistProfiles()
    }

    private func loadActiveProfile() {
        guard profiles.indices.contains(activeProfileIndex) else { return }
        candidates = profiles[activeProfileIndex].candidates
        selectedCandidateID = profiles[activeProfileIndex].selectedCandidateID
        phase = candidates.isEmpty ? .idle : .completed
        progress = candidates.isEmpty ? 0 : 1
        validationWarning = nil
        validationSummary = nil
    }

    private func bestCandidate(in candidates: [ScoutingCandidate]) -> ScoutingCandidate? {
        candidates
            .filter { $0.isUsable }
            .min { lhs, rhs in
                let leftBucket = lhs.bucketRawValue ?? Int.max
                let rightBucket = rhs.bucketRawValue ?? Int.max
                if leftBucket != rightBucket { return leftBucket < rightBucket }
                let leftRTT = lhs.rttMilliseconds ?? .infinity
                let rightRTT = rhs.rttMilliseconds ?? .infinity
                if leftRTT != rightRTT { return leftRTT < rightRTT }
                return lhs.lossPercentage < rhs.lossPercentage
            }
    }

    private func persistProfiles() {
        guard let data = try? JSONEncoder().encode(profiles) else { return }
        defaults.set(data, forKey: storageKey)
    }
}
