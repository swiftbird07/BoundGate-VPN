// swift-tools-version:5.9
import PackageDescription

// BoundGate for macOS: a menu-bar front end for the boundgate-node daemon.
// No dependencies. `make mac-app` builds this package and assembles the bundle.
let package = Package(
    name: "BoundGate",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        // for the iOS app and its packet tunnel (apps/ios)
        .library(name: "BoundGateKit", targets: ["BoundGateKit"]),
        .library(name: "BoundGateUI", targets: ["BoundGateUI"]),
    ],
    targets: [
        // daemon socket client and models; no UI
        .target(name: "BoundGateKit"),
        // views, theme, app model
        .target(name: "BoundGateUI", dependencies: ["BoundGateKit"]),
        // the menu-bar app
        .executableTarget(name: "BoundGate", dependencies: ["BoundGateUI"]),
        // Secure Enclave bridge for the daemon's device key (key_kind: secure-enclave)
        .executableTarget(name: "boundgate-sekey"),
        // developer tool: talk to a daemon, render the UI states to PNG, draw the app icon
        .executableTarget(name: "bgtool", dependencies: ["BoundGateUI"]),
    ]
)
