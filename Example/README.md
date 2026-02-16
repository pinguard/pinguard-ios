# PinGuard Example App

A comprehensive demonstration of all PinGuard SDK features.

## Overview

This Example app showcases every public API and feature of the PinGuard certificate pinning SDK through an interactive feature gallery.

## Features Demonstrated

### 1. Configuration & Setup
- Builder pattern for configuration
- Multiple environment support (dev, uat, prod)
- Telemetry callback integration
- Dynamic environment selection

### 2. Pin Creation & Types
- SPKI (Subject Public Key Info) hashing
- Certificate hashing
- Pin types: `.spki`, `.certificate`, `.ca`
- Pin roles: `.primary`, `.backup`
- Pin scopes: `.leaf`, `.intermediate`, `.root`, `.any`

### 3. Policy Configuration
- Host pattern matching (exact vs wildcard)
- Fail strategies (strict vs permissive)
- System trust options
- Policy sets with default policies

### 4. Trust Evaluation
- Direct evaluation with `PinGuard.shared.evaluate()`
- `TrustDecision` inspection
- Decision reasons
- Event capture

### 5. URLSession Integration
- `PinGuardSession` wrapper (drop-in replacement)
- `PinGuardURLSessionDelegate` for custom setups
- Automatic pinning on network requests

### 6. mTLS (Mutual TLS)
- Client certificate sources: PKCS12, Keychain
- `ClientCertificateProvider` protocol
- Identity loading and management
- Renewal callbacks

### 7. Events & Telemetry
- All 12 event types
- Event capture and logging
- `ChainSummary` metadata
- Built-in `PinGuardLogger`

### 8. Remote Configuration
- Signed configuration blobs
- HMAC-SHA256 verification
- Public key (ECDSA) verification
- Security threat model documentation

### 9. Error Handling
- All 9 `PinGuardError` cases
- Recovery strategies
- Decision reason handling

### 10. Environment Management
- Runtime environment switching
- Configuration updates
- Active policy inspection

## Architecture

```
Example/
├── ExampleApp.swift              # App entry point
├── FeatureGallery.swift           # Main navigation
├── DemoViewTemplate.swift         # Reusable demo template
└── Demos/
    ├── ConfigurationDemoView.swift
    ├── PinGenerationDemoView.swift
    ├── PolicyConfigDemoView.swift
    ├── TrustEvaluationDemoView.swift
    ├── URLSessionDemoView.swift
    ├── MTLSDemoView.swift
    ├── EventsDemoView.swift
    ├── RemoteConfigDemoView.swift
    ├── ErrorHandlingDemoView.swift
    └── EnvironmentDemoView.swift
```

## Building & Running

### Prerequisites
- Xcode 15+
- iOS 15+ deployment target
- Swift 5.9+

### Build

```bash
cd Example
open Example.xcodeproj

# Or with xcodebuild
xcodebuild -scheme Example -destination 'platform=iOS Simulator,name=iPhone 15'
```

### Run

1. Open `Example.xcodeproj` in Xcode
2. Select a simulator or device
3. Press Cmd+R to build and run
4. Browse the Feature Gallery
5. Tap any feature to see its demo

## Demo Execution

Each demo screen includes:

1. **Description** - Brief explanation of the feature
2. **Code Snippet** - Actual usage code
3. **Interactive UI** - Feature-specific controls
4. **Run Demo Button** - Execute the demonstration
5. **Output** - Results and detailed information

Most demos are **offline** and don't require network access, using simulated data and local resources.

## Live Network Testing

The **URLSession Integration** demo includes a live test button that:
- Makes a real HTTPS request to example.com
- Validates certificate pins
- Shows success/failure status
- Displays response metadata

**Note**: Pin hashes for example.com are configured in `ExampleApp.swift` using **permissive mode**
for demonstration purposes. This allows the app to function even if pins mismatch, while still
logging all pinning events. Production apps should use **strict mode** (`failStrategy: .strict`).

## Code Structure

### DemoViewTemplate

All demos use a consistent template that provides:
- Title and description
- Syntax-highlighted code snippet
- Custom interactive content
- Run button with loading state
- Output display area

### Async Execution

Demos use `async/await` for clean asynchronous code:

```swift
DemoViewTemplate(
    title: "Feature Name",
    description: "What it does",
    codeSnippet: "...",
    action: {
        await performDemo()
    }
) {
    // Custom UI content
}
```

## What's NOT Covered

- **Live remote configuration fetching** - Requires backend infrastructure
- **Real mTLS with valid certificates** - Requires PKI setup
- **Production certificate validation** - Uses example.com only

These limitations are documented in each relevant demo screen.

## Extending the Example

To add a new demo:

1. Create `NewFeatureDemoView.swift` in `Demos/`
2. Use `DemoViewTemplate` for consistency
3. Add to `features` array in `FeatureGalleryView`
4. Implement demo logic with clear output

Example:

```swift
struct NewFeatureDemoView: View {
    var body: some View {
        DemoViewTemplate(
            title: "New Feature",
            description: "Description here",
            codeSnippet: "Code here",
            action: { await performDemo() }
        ) {
            // Custom UI
        }
    }
}

func performDemo() async -> String {
    // Demo implementation
    return "Output"
}
```

## Testing

The Example app serves as an integration test suite for PinGuard. All public APIs are exercised with visible results.

## License

Same as PinGuard SDK.
