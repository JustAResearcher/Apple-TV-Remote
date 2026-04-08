package com.example.appletvremote.protocol

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

object MrpDiagnostic {

    private fun trustAll() = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?) {}
        override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    })

    suspend fun diagnose(host: String, port: Int, clientId: String): String = withContext(Dispatchers.IO) {
        val report = StringBuilder()
        report.appendLine("=== MRP Diagnostic ===")
        report.appendLine("Target: $host:$port")

        // Test 1: Plain TCP — send data immediately without reading
        report.appendLine("\n--- Test 1: Plain TCP send first ---")
        try {
            val sock = Socket()
            sock.connect(InetSocketAddress(host, port), 5000)
            sock.soTimeout = 5000
            sock.tcpNoDelay = true
            val msg = ProtobufHelper.buildDeviceInfoMessage(clientId, "Android Remote")
            val packet = encodeVarint(msg.size) + msg
            sock.getOutputStream().write(packet)
            sock.getOutputStream().flush()
            val buf = ByteArray(2048)
            val n = sock.getInputStream().read(buf)
            if (n == -1) {
                report.appendLine("Plain TCP: Sent ${packet.size}B, server closed")
            } else {
                report.appendLine("Plain TCP: Got $n bytes back!")
                report.appendLine("Hex: ${buf.take(minOf(n, 100)).joinToString(" ") { "%02x".format(it) }}")
            }
            sock.close()
        } catch (e: Exception) {
            report.appendLine("Plain TCP: ${e.javaClass.simpleName}: ${e.message}")
        }

        // Test 2: TLS with default settings
        report.appendLine("\n--- Test 2: TLS default ---")
        testTls(report, host, port, clientId, "TLSv1.2", null)

        // Test 3: TLS with TLSv1.3
        report.appendLine("\n--- Test 3: TLS 1.3 ---")
        testTls(report, host, port, clientId, "TLSv1.3", null)

        // Test 4: TLS 1.2 with ALPN
        report.appendLine("\n--- Test 4: TLS + ALPN ---")
        testTls(report, host, port, clientId, "TLSv1.2", arrayOf("MediaRemoteTV", "airplay", "companion"))

        // Test 5: Direct SSLSocket (no plain socket upgrade)
        report.appendLine("\n--- Test 5: Direct SSLSocket ---")
        try {
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, trustAll(), SecureRandom())
            val ssl = ctx.socketFactory.createSocket() as SSLSocket
            ssl.connect(InetSocketAddress(host, port), 5000)
            ssl.soTimeout = 5000
            ssl.startHandshake()
            report.appendLine("Direct SSL: OK (${ssl.session.protocol})")
            val msg = ProtobufHelper.buildDeviceInfoMessage(clientId, "Android Remote")
            val packet = encodeVarint(msg.size) + msg
            ssl.outputStream.write(packet)
            ssl.outputStream.flush()
            val buf = ByteArray(2048)
            val n = ssl.inputStream.read(buf)
            if (n == -1) {
                report.appendLine("Response: closed")
            } else {
                report.appendLine("Response: $n bytes")
                report.appendLine("Hex: ${buf.take(minOf(n, 100)).joinToString(" ") { "%02x".format(it) }}")
            }
            ssl.close()
        } catch (e: Exception) {
            report.appendLine("Direct SSL: ${e.javaClass.simpleName}: ${e.message}")
        }

        report.toString()
    }

    private fun testTls(
        report: StringBuilder,
        host: String,
        port: Int,
        clientId: String,
        protocol: String,
        alpn: Array<String>?
    ) {
        try {
            val ctx = SSLContext.getInstance(protocol)
            ctx.init(null, trustAll(), SecureRandom())

            val plain = Socket()
            plain.connect(InetSocketAddress(host, port), 5000)
            val ssl = ctx.socketFactory.createSocket(plain, host, port, true) as SSLSocket
            ssl.soTimeout = 5000

            // Set ALPN if provided
            if (alpn != null) {
                try {
                    val params = ssl.sslParameters
                    params.applicationProtocols = alpn
                    ssl.sslParameters = params
                    report.appendLine("ALPN set: ${alpn.joinToString()}")
                } catch (e: Exception) {
                    report.appendLine("ALPN not supported: ${e.message}")
                }
            }

            ssl.startHandshake()
            report.appendLine("Handshake: OK (${ssl.session.protocol}, ${ssl.session.cipherSuite})")

            // Send DeviceInfo
            val msg = ProtobufHelper.buildDeviceInfoMessage(clientId, "Android Remote")
            val packet = encodeVarint(msg.size) + msg
            ssl.outputStream.write(packet)
            ssl.outputStream.flush()

            val buf = ByteArray(2048)
            val n = ssl.inputStream.read(buf)
            if (n == -1) {
                report.appendLine("Response: server closed")
            } else {
                report.appendLine("Response: $n bytes")
                report.appendLine("Hex: ${buf.take(minOf(n, 100)).joinToString(" ") { "%02x".format(it) }}")
            }
            ssl.close()
            plain.close()
        } catch (e: Exception) {
            report.appendLine("Failed: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun encodeVarint(value: Int): ByteArray {
        if (value < 0x80) return byteArrayOf(value.toByte())
        val result = mutableListOf<Byte>()
        var v = value
        while (v > 0x7F) {
            result.add(((v and 0x7F) or 0x80).toByte())
            v = v ushr 7
        }
        result.add((v and 0x7F).toByte())
        return result.toByteArray()
    }
}
