//
//  ExampleApp.swift
//  Example
//
//  Created by Çağatay Eğilmez on 3.02.2026.
//

import PinGuard
import SwiftUI

@main
struct ExampleApp: App {

    @State private var eventLog = EventLog()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(eventLog)
                .task {
                    await PinGuardSetup.configure(eventLog: eventLog)
                }
        }
    }
}
