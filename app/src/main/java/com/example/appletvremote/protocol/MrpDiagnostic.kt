package com.example.appletvremote.protocol

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Raw diagnostic tool — connects to Apple TV and dumps exactly
 * what happens on the wire. No assumptions about framing.
 */
object MrpDiagnostic {
    private const val TAG = "MrpDiagnostic"

    suspend fun diagnose(host: String, port: Int, clientId: String): String = withContext(Dispatchers.IO) {
        val report = StringBuilder()
        report.appendLine("=== MRP Diagnostic ===")
        report.appendLine("Target: $host:$port")

        var socket: Socket? = null
        try {
            // Step 1: TCP connect
            socket = Socket()
            socket.connect(InetSocketAddress(host, port), 5000)
            socket.soTimeout = 3000
            socket.tcpNoDelay = true
            report.appendLine("TCP: Connected OK")

            val input = socket.getInputStream()
            val output = socket.getOutputStream()

            // Step 2: Check if Apple TV sends anything first
            report.appendLine("\n--- Checking if server speaks first (3s timeout) ---")
            try {
                val firstByte = input.read()
                if (firstByte == -1) {
                    report.appendLine("Server: Closed connection immediately!")
                    return@withContext report.toString()
                }
                // Read more if available
                val buf = ByteArray(1024)
                buf[0] = firstByte.toByte()
                var count = 1
                try {
                    socket.soTimeout = 500
                    val more = input.read(buf, 1, 1023)
                    if (more > 0) count += more
                } catch (_: Exception) {}
                val hex = buf.take(count).joinToString(" ") { "%02x".format(it) }
                report.appendLine("Server sent first ($count bytes): $hex")

                // Check if it looks like TLS ServerHello
                if (firstByte == 0x16 || firstByte == 0x15) {
                    report.appendLine(">>> LOOKS LIKE TLS! First byte 0x${"%02x".format(firstByte)} is TLS record type")
                    report.appendLine(">>> Apple TV expects TLS on this port!")
                }
                // Check if it looks like a varint-prefixed protobuf
                if (firstByte < 0x80) {
                    report.appendLine(">>> First byte could be varint length: $firstByte")
                    report.appendLine(">>> Apple TV may be sending a message without us asking")
                }
            } catch (e: java.net.SocketTimeoutException) {
                report.appendLine("Server: Silent (no data in 3s) — client should speak first")
            }

            // Step 3: Reconnect (previous socket may be in bad state)
            socket.close()
            socket = Socket()
            socket.connect(InetSocketAddress(host, port), 5000)
            socket.soTimeout = 5000
            socket.tcpNoDelay = true
            val input2 = socket.getInputStream()
            val output2 = socket.getOutputStream()

            // Step 4: Build and send DeviceInfo
            val msg = ProtobufHelper.buildDeviceInfoMessage(clientId, "Android Remote")
            val varintLen = encodeVarint(msg.size)
            val fullPacket = varintLen + msg

            report.appendLine("\n--- Sending DeviceInfo ---")
            report.appendLine("Protobuf size: ${msg.size} bytes")
            report.appendLine("Varint prefix: ${varintLen.joinToString(" ") { "%02x".format(it) }}")
            report.appendLine("First 80 bytes: ${fullPacket.take(80).joinToString(" ") { "%02x".format(it) }}")

            output2.write(fullPacket)
            output2.flush()
            report.appendLine("Sent OK")

            // Step 5: Try to read response
            report.appendLine("\n--- Reading response ---")
            try {
                val respBuf = ByteArray(2048)
                val read = input2.read(respBuf)
                if (read == -1) {
                    report.appendLine("Response: Connection closed by Apple TV (read returned -1)")
                    report.appendLine(">>> Apple TV rejected our message!")
                } else {
                    val respHex = respBuf.take(read).joinToString(" ") { "%02x".format(it) }
                    report.appendLine("Response ($read bytes): $respHex")

                    // Check if response starts with TLS
                    if (read > 0 && (respBuf[0].toInt() and 0xFF) == 0x16) {
                        report.appendLine(">>> Response looks like TLS ServerHello!")
                    }
                    // Try parsing as varint
                    if (read > 0) {
                        val firstByte2 = respBuf[0].toInt() and 0xFF
                        if (firstByte2 < 0x80) {
                            report.appendLine(">>> First byte as varint length: $firstByte2 (total read: $read)")
                        }
                    }
                }
            } catch (e: java.net.SocketTimeoutException) {
                report.appendLine("Response: Timeout (5s) — Apple TV accepted but didn't respond")
            } catch (e: Exception) {
                report.appendLine("Response error: ${e.javaClass.simpleName}: ${e.message}")
            }

        } catch (e: Exception) {
            report.appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            try { socket?.close() } catch (_: Exception) {}
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
