//
//  NoopChallengeSender.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation

final class NoopChallengeSender: NSObject, URLAuthenticationChallengeSender {

    func use(_ credential: URLCredential,
             for challenge: URLAuthenticationChallenge) {}

    func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}

    func cancel(_ challenge: URLAuthenticationChallenge) {}
}
