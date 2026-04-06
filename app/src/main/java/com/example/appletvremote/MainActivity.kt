package com.example.appletvremote

import android.os.Bundle
import android.app.Activity
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Absolute minimum — plain Android View, no Compose, no AppCompat, no themes
        val tv = TextView(this).apply {
            text = "ATV Remote - Loading..."
            textSize = 24f
            setPadding(48, 100, 48, 48)
        }
        setContentView(tv)
    }
}
