// swift-tools-version:5.9
import PackageDescription

// BoundGate for macOS: a menu-bar front end for the boundgate-node daemon.
// No dependencies. `make mac-app` builds this package and assembles the bundle.
let package = Package(
    name: "BoundGate",
    platforms: [.macOS(.v13)],
    targets: [
        // daemon socket client and models; no UI
        .target(name: "BoundGateKit"),
        // views, theme, app model
        .target(name: "BoundGateUI", dependencies: ["BoundGateKit"]),
        // the menu-bar app
        .executableTarget(name: "BoundGate", dependencies: ["BoundGateUI"]),
        // developer tool: talk to a daemon, render the UI states to PNG, draw the app icon
        .executableTarget(name: "bgtool", dependencies: ["BoundGateUI"]),
    ]
)
