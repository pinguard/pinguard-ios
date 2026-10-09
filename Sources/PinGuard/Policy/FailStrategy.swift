//
//  FailStrategy.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

/// How a policy reacts when system trust or pin matching fails.
public enum FailStrategy: String, Codable, Sendable {

    /// Fail immediately when trust or pinning checks fail.
    case strict

    /// Allow the connection to proceed despite failures under a permissive policy.
    case permissive
}
