//
//  CallCounter.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation

final class CallCounter: @unchecked Sendable {

    private let lock = NSLock()
    private var storage = 0

    var count: Int {
        lock.withLock {
            storage
        }
    }

    /// Increments the counter.
    func increment() {
        lock.withLock {
            storage += 1
        }
    }
}
