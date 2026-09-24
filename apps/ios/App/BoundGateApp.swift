import SwiftUI
import UserNotifications
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
        // the tunnel notifies when the session ended and a sign-in is
        // needed (PacketTunnelProvider.statusChanged); the permission is
        // the app's to ask for
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    var body: some Scene {
        WindowGroup { MobileView(model: model) }
    }
}
