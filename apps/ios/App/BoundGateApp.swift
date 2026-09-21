import SwiftUI
import BoundGateUI

@main
struct BoundGateApp: App {
    @StateObject private var tunnel: TunnelController
    @StateObject private var model: MobileModel

    init() {
        let t = TunnelController()
        _tunnel = StateObject(wrappedValue: t)
        let m = MobileModel(tunnel: t)
        m.start()
        _model = StateObject(wrappedValue: m)
    }

    var body: some Scene {
        WindowGroup { MobileView(model: model) }
    }
}
