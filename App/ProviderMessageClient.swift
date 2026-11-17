import Foundation
import NetworkExtension

enum ProviderMessageClientError: LocalizedError {
    case timeout
    case emptyResponse

    var errorDescription: String? {
        switch self {
        case .timeout:
            return "Core unavailable: ядро не ответило на запрос статистики вовремя."
        case .emptyResponse:
            return "Core unavailable: ядро вернуло пустой ответ статистики."
        }
    }
}

/// Отправляет stats request и гарантирует ровно одно завершение continuation,
/// даже если provider одновременно ответил и сработал локальный timeout.
enum ProviderMessageClient {
    static func stats(
        from session: NETunnelProviderSession,
        timeout: TimeInterval = 3
    ) async throws -> Data {
        let message = try JSONSerialization.data(withJSONObject: [
            "command": "stats",
            "request": "stats"
        ])
        return try await withCheckedThrowingContinuation { continuation in
            let gate = ResumeGate(continuation)
            do {
                try session.sendProviderMessage(message) { response in
                    if let response, !response.isEmpty {
                        gate.resume(.success(response))
                    } else {
                        gate.resume(.failure(ProviderMessageClientError.emptyResponse))
                    }
                }
            } catch {
                gate.resume(.failure(error))
            }
            Task {
                do {
                    try await Task.sleep(for: .milliseconds(Int(timeout * 1000)))
                    gate.resume(.failure(ProviderMessageClientError.timeout))
                } catch {
                    // Отмена timeout не отменяет уже завершённый provider callback.
                }
            }
        }
    }

    private final class ResumeGate {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Data, Error>?

        init(_ continuation: CheckedContinuation<Data, Error>) {
            self.continuation = continuation
        }

        func resume(_ result: Result<Data, Error>) {
            lock.lock()
            let continuation = continuation
            self.continuation = nil
            lock.unlock()
            continuation?.resume(with: result)
        }
    }
}
