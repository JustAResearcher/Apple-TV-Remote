package com.example.appletvremote

import android.app.Activity
import android.os.Bundle
import android.widget.ScrollView
import android.widget.TextView

/**
 * Minimal activity that shows a crash stacktrace using plain Android Views (no Compose).
 * If THIS crashes too, the problem is in the manifest or dex loading.
 */
class CrashActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val trace = intent?.getStringExtra("crash_trace") ?: "No crash info available"
        val tv = TextView(this).apply {
            text = "CRASH LOG:\n\n$trace"
            textSize = 12f
            setPadding(32, 64, 32, 32)
            setTextIsSelectable(true)
        }
        val sv = ScrollView(this).apply { addView(tv) }
        setContentView(sv)
    }
}
