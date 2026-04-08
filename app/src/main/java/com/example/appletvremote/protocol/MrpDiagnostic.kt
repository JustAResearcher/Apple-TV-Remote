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
    private const val TAG = "MrpDiagnostic"

    suspend fun diagnose(host: String, port: Int, clientId: String): String = withContext(Dispatchers.IO) {
        val report = StringBuilder()
        report.appendLine("=== MRP Diagnostic ===")
        report.appendLine("Target: $host:$port")

        // Test 1: Plain TCP
        report.appendLine("\n--- Test 1: Plain TCP ---")
        try {
            val sock = Socket()
            sock.connect(InetSocketAddress(host, port), 5000)
            sock.soTimeout = 3000
            report.appendLine("TCP connect: OK")
            try {
                val b = sock.getInputStream().read()
                if (b == -1) {
                    report.appendLine("Plain TCP: Server closed immediately")
                    report.appendLine(">>> Plain TCP rejected")
                } else {
                    report.appendLine("Plain TCP: Server sent first byte: 0x${"%02x".format(b)}")
                }
            } catch (e: java.net.SocketTimeoutException) {
                report.appendLine("Plain TCP: Server silent (3s timeout)")
                report.appendLine(">>> Server waits for client to speak")
            } catch (e: Exception) {
                report.appendLine("Plain TCP read: ${e.javaClass.simpleName}: ${e.message}")
            }
            sock.close()
        } catch (e: Exception) {
            report.appendLine("TCP connect failed: ${e.message}")
        }

        // Test 2: TLS
        report.appendLine("\n--- Test 2: TLS ---")
        try {
            val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?) {}
                override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            })
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, trustAll, SecureRandom())

            val plain = Socket()
            plain.connect(InetSocketAddress(host, port), 5000)
            val ssl = ctx.socketFactory.createSocket(plain, host, port, true) as SSLSocket
            ssl.soTimeout = 5000
            ssl.startHandshake()
            report.appendLine("TLS handshake: OK (${ssl.session.protocol}, ${ssl.session.cipherSuite})")

            // TLS works! Now send DeviceInfo and see what comes back
            val msg = ProtobufHelper.buildDeviceInfoMessage(clientId, "Android Remote")
            val varint = encodeVarint(msg.size)
            val packet = varint + msg
            report.appendLine("Sending DeviceInfo: ${packet.size} bytes")
            report.appendLine("Hex: ${packet.take(60).joinToString(" ") { "%02x".format(it) }}...")

            ssl.outputStream.write(packet)
            ssl.outputStream.flush()
            report.appendLine("Sent OK")

            // Read response
            ssl.soTimeout = 5000
            try {
                val buf = ByteArray(4096)
                val n = ssl.inputStream.read(buf)
                if (n == -1) {
                    report.appendLine("TLS response: Server closed after our message")
                    report.appendLine(">>> DeviceInfo rejected over TLS")
                } else {
                    report.appendLine("TLS response: $n bytes")
                    report.appendLine("Hex: ${buf.take(n).joinToString(" ") { "%02x".format(it) }}")

                    // Try to parse as varint + protobuf
                    val firstByte = buf[0].toInt() and 0xFF
                    if (firstByte < 0x80) {
                        report.appendLine(">>> Varint length: $firstByte, total received: $n")
                        if (n > 1) {
                            val protoBytes = buf.copyOfRange(1, n)
                            val parsed = ProtobufHelper.parseMessage(protoBytes)
                            val msgType = parsed[1] as? Long
                            report.appendLine(">>> Protobuf type: $msgType, fields: ${parsed.keys}")
                            if (msgType == 15L) {
                                report.appendLine(">>> GOT DEVICE_INFO RESPONSE! Protocol is working!")
                            }
                        }
                    } else {
                        // Multi-byte varint
                        val (len, off) = ProtobufHelper.decodeVarint(buf, 0)
                        report.appendLine(">>> Varint length: $len (${off} bytes prefix)")
                        if (n >= off + len) {
                            val protoBytes = buf.copyOfRange(off, off + len.toInt())
                            val parsed = ProtobufHelper.parseMessage(protoBytes)
                            val msgType = parsed[1] as? Long
                            report.appendLine(">>> Protobuf type: $msgType, fields: ${parsed.keys}")
                        }
                    }
                }
            } catch (e: java.net.SocketTimeoutException) {
                report.appendLine("TLS response: Timeout (5s)")
            } catch (e: Exception) {
                report.appendLine("TLS response: ${e.javaClass.simpleName}: ${e.message}")
            }
            ssl.close()
            plain.close()
        } catch (e: Exception) {
            report.appendLine("TLS failed: ${e.javaClass.simpleName}: ${e.message}")
        }

        report.toString()
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
