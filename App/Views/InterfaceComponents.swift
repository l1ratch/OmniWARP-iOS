import SwiftUI

struct ScreenHeading: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.largeTitle.weight(.bold))
            Text(subtitle)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}

struct NoticeView: View {
    enum Tone {
        case neutral
        case success
        case warning
        case error

        var color: Color {
            switch self {
            case .neutral: return .secondary
            case .success: return .green
            case .warning: return .orange
            case .error: return .red
            }
        }
    }

    let title: String
    let message: String?
    var tone: Tone = .neutral

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: iconName)
                .foregroundStyle(tone.color)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.subheadline.weight(.medium))
                if let message, !message.isEmpty {
                    Text(message)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tone.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private var iconName: String {
        switch tone {
        case .neutral: return "info.circle"
        case .success: return "checkmark.circle"
        case .warning: return "exclamationmark.triangle"
        case .error: return "xmark.octagon"
        }
    }
}

struct DetailRow: View {
    let title: String
    let value: String
    var monospaced = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(title)
                .foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value)
                .font(monospaced ? .body.monospaced() : .body)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
        .font(.subheadline)
    }
}

struct LabeledNumberField: View {
    let title: String
    @Binding var value: String
    var prompt: String = "0"

    var body: some View {
        HStack {
            Text(title)
                .font(.subheadline)
            Spacer(minLength: 16)
            TextField(prompt, text: $value)
                .keyboardType(.numberPad)
                .multilineTextAlignment(.trailing)
                .monospaced()
                .frame(maxWidth: 150)
                .accessibilityLabel(title)
        }
    }
}

extension UInt64 {
    var formattedTraffic: String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: self), countStyle: .binary)
    }
}

extension Date {
    var formattedHandshake: String {
        formatted(date: .abbreviated, time: .standard)
    }
}
