//
//  EventLogView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import SwiftUI

struct EventLogView: View {

    @Environment(EventLog.self) private var eventLog

    var body: some View {
        List(eventLog.entries) { entry in
            VStack(alignment: .leading, spacing: 4) {
                Text(entry.message)
                    .font(.body)
                Text(entry.date, style: .time)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .overlay {
            if eventLog.entries.isEmpty {
                ContentUnavailableView("No events yet", systemImage: "list.bullet.rectangle")
            }
        }
        .toolbar {
            Button("Clear") {
                eventLog.clear()
            }
            .disabled(eventLog.entries.isEmpty)
        }
        .navigationTitle("Event log")
    }
}
