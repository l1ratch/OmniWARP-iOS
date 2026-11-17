import Foundation

/// A validated domain-list rule. Plain rules match the apex and its subdomains;
/// `*.` rules match subdomains only.
public struct DomainRule: Hashable, Sendable {
    public let domain: String
    public let isWildcard: Bool

    public init(_ value: String) throws {
        var candidate = value.trimmingCharacters(in: .whitespacesAndNewlines)
        var wildcard = false

        if candidate.hasPrefix("*.") {
            wildcard = true
            candidate.removeFirst(2)
        }

        if candidate.contains("*") {
            throw DomainListError.invalidWildcard
        }

        self.domain = try DomainList.normalize(candidate)
        self.isWildcard = wildcard
    }

    public init(domain: String, isWildcard: Bool) throws {
        if domain.contains("*") {
            throw DomainListError.invalidWildcard
        }
        self.domain = try DomainList.normalize(domain)
        self.isWildcard = isWildcard
    }

    public func matches(_ host: String) -> Bool {
        guard let normalizedHost = try? DomainList.normalize(host) else {
            return false
        }

        if isWildcard {
            return normalizedHost.count > domain.count && normalizedHost.hasSuffix("." + domain)
        }

        return normalizedHost == domain ||
            (normalizedHost.count > domain.count && normalizedHost.hasSuffix("." + domain))
    }
}

public enum DomainListError: Error, Equatable, Sendable {
    case empty
    case nameTooLong
    case emptyLabel
    case labelTooLong(String)
    case invalidHyphen(String)
    case invalidCharacter(String)
    case invalidWildcard
    case invalidPunycodeLabel(String)
}

public struct DomainListParseIssue: Error, Equatable, Sendable {
    public let line: Int
    public let value: String
    public let reason: DomainListError

    public init(line: Int, value: String, reason: DomainListError) {
        self.line = line
        self.value = value
        self.reason = reason
    }
}

public struct DomainListParseResult: Sendable {
    public let rules: [DomainRule]
    public let issues: [DomainListParseIssue]

    public init(rules: [DomainRule], issues: [DomainListParseIssue]) {
        self.rules = rules
        self.issues = issues
    }
}

/// Pure parser and matcher for itdoginfo-compatible `.lst` files.
public enum DomainList {
    /// Lowercases and canonicalizes a host, removes one trailing root dot, and
    /// performs basic ASCII/IDN label validation. It intentionally does not
    /// attempt full IDNA2008/Punycode conversion.
    public static func normalize(_ host: String) throws -> String {
        var value = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasSuffix(".") {
            value.removeLast()
        }

        guard !value.isEmpty else {
            throw DomainListError.empty
        }
        guard value.utf8.count <= 253 else {
            throw DomainListError.nameTooLong
        }

        value = value.precomposedStringWithCanonicalMapping.lowercased()
        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else {
            throw DomainListError.empty
        }

        for substring in labels {
            let label = String(substring)
            guard !label.isEmpty else {
                throw DomainListError.emptyLabel
            }
            guard label.utf8.count <= 63 else {
                throw DomainListError.labelTooLong(label)
            }
            guard !label.hasPrefix("-"), !label.hasSuffix("-") else {
                throw DomainListError.invalidHyphen(label)
            }
            if label.hasPrefix("xn--") && label.count == 4 {
                throw DomainListError.invalidPunycodeLabel(label)
            }

            for scalar in label.unicodeScalars {
                if scalar.value < 128 {
                    guard (scalar.value >= 97 && scalar.value <= 122) ||
                        (scalar.value >= 48 && scalar.value <= 57) || scalar.value == 45 else {
                        throw DomainListError.invalidCharacter(label)
                    }
                } else {
                    // Basic IDN acceptance: letters, decimal digits and combining
                    // marks. Emoji, whitespace, slashes and punctuation are rejected.
                    guard CharacterSet.letters.contains(scalar) ||
                        CharacterSet.decimalDigits.contains(scalar) ||
                        CharacterSet.nonBaseCharacters.contains(scalar) else {
                        throw DomainListError.invalidCharacter(label)
                    }
                }
            }
        }

        return value
    }

    public static func parseLine(_ line: String) throws -> DomainRule? {
        let withoutComment = line.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
        let value = withoutComment.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else {
            return nil
        }
        return try DomainRule(value)
    }

    /// Parses all valid lines. Use `parseDetailed` when malformed-line reporting
    /// is needed; invalid lines never make otherwise valid rules disappear.
    public static func parse(_ text: String) -> [DomainRule] {
        parseDetailed(text).rules
    }

    public static func parseDetailed(_ text: String) -> DomainListParseResult {
        var rules: [DomainRule] = []
        var issues: [DomainListParseIssue] = []
        var seen: Set<DomainRule> = []

        for (index, line) in text.components(separatedBy: .newlines).enumerated() {
            do {
                if let rule = try parseLine(line), seen.insert(rule).inserted {
                    rules.append(rule)
                }
            } catch let error as DomainListError {
                issues.append(DomainListParseIssue(line: index + 1, value: line, reason: error))
            } catch {
                issues.append(DomainListParseIssue(line: index + 1, value: line, reason: .invalidCharacter(line)))
            }
        }

        return DomainListParseResult(rules: rules, issues: issues)
    }

    public static func contains(_ host: String, in rules: [DomainRule]) -> Bool {
        rules.contains { $0.matches(host) }
    }

    public static func contains(_ host: String, in domains: [String]) -> Bool {
        domains.contains { rawRule in
            guard let rule = try? DomainRule(rawRule) else { return false }
            return rule.matches(host)
        }
    }
}
