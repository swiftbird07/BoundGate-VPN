import SwiftUI
import BoundGateUI

@main
struct BoundGateApp: App {
    @StateObject private var model: AppModel = {
        let m = AppModel()
        m.start()
        return m
    }()

    var body: some Scene {
        MenuBarExtra {
            PanelView(model: model)
        } label: {
            Image(nsImage: MenuBarIcon.image(connected: model.isConnected, attention: model.needsAttention))
        }
        .menuBarExtraStyle(.window)
    }
}
