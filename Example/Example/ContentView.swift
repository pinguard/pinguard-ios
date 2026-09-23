//
//  ContentView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import SwiftUI

struct ContentView: View {

    var body: some View {
        NavigationStack {
            List {
                Section("Try it") {
                    NavigationLink("Live request to example.com", value: DemoScreen.liveRequest)
                    NavigationLink("Compute a pin from a certificate", value: DemoScreen.pinHash)
                    NavigationLink("Which policy matches a host?", value: DemoScreen.hostMatching)
                    NavigationLink("Apply a signed remote config", value: DemoScreen.remoteConfig)
                }
                Section("Observe") {
                    NavigationLink("Event log", value: DemoScreen.eventLog)
                }
            }
            .navigationTitle("PinGuard")
            .navigationDestination(for: DemoScreen.self) { screen in
                switch screen {
                case .liveRequest:
                    LiveRequestView()
                case .pinHash:
                    PinHashView()
                case .hostMatching:
                    HostMatchingView()
                case .remoteConfig:
                    RemoteConfigView()
                case .eventLog:
                    EventLogView()
                }
            }
        }
    }
}
