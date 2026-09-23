//
//  PinRole.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public enum PinRole: String, Codable, Sendable {

    /// Primary pin used for normal validation.
    case primary

    /// Backup pin used for key rotation or as a fallback.
    case backup
}
