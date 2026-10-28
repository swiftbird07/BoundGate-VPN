package com.net407.boundgate

import android.app.Application

class App : Application() {
    lateinit var node: Node
        private set

    override fun onCreate() {
        super.onCreate()
        DebugLog.init(this)
        node = Node(this)
    }
}
