//
//  EventLogEntry.swift
//  Example
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation

struct EventLogEntry: Identifiable {

    let id = UUID()
    let date: Date
    let message: String
}
