//
//  SystemTrustResult.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

struct SystemTrustResult: Equatable, Sendable {

    let isTrusted: Bool
    let errorDescription: String?
}
