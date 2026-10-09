//
//  RemoteConfigThreatModel.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

/// Reference text that explains why PinGuard refuses unsigned remote configuration.
public enum RemoteConfigThreatModel {

    /// The warning to show or log when someone tries to ship pins without a signature.
    public static let unsignedConfigWarning =
        "Unsigned remote configuration is insecure; it allows a network attacker to disable pinning."
}
