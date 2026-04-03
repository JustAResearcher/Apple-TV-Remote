package com.example.appletvremote

import android.app.Application
import android.content.Intent
import android.util.Log
import java.io.PrintWriter
import java.io.StringWriter

class App : Application() {
    override fun onCreate() {
        super.onCreate()

        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                val sw = StringWriter()
                throwable.printStackTrace(PrintWriter(sw))
                val trace = sw.toString()
                Log.e("AppCrash", trace)

                val intent = Intent(this, CrashActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                    putExtra("crash_trace", trace)
                }
                startActivity(intent)
            } catch (_: Exception) {
                defaultHandler?.uncaughtException(thread, throwable)
            }
        }
    }
}
