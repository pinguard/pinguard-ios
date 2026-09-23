//
//  PinMatcher.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

struct PinMatcher: Sendable {

    /// Returns every pin that matches at least one in-scope certificate of the chain.
    ///
    /// - Parameters:
    ///   - pins: The pins configured for the host.
    ///   - candidates: The candidate certificates derived from the chain.
    /// - Returns: The subset of pins that matched.
    func matchedPins(_ pins: [Pin], in candidates: [CertificateCandidate]) -> [Pin] {
        pins.filter { pin in
            candidates.contains { matches(pin: pin, candidate: $0) }
        }
    }

    /// Checks whether a single pin matches a single certificate candidate.
    ///
    /// - Parameters:
    ///   - pin: The pin to test.
    ///   - candidate: The certificate candidate to test against.
    /// - Returns: `true` when the candidate is in scope and carries the pinned hash.
    private func matches(pin: Pin, candidate: CertificateCandidate) -> Bool {
        guard candidate.scope.contains(pin.scope) else {
            return false
        }

        switch pin.type {
        case .spki:
            return candidate.spkiHash == pin.hash
        case .certificate:
            return candidate.certificateHash == pin.hash
        case .ca:
            return candidate.scope.isCA && candidate.certificateHash == pin.hash
        }
    }
}
