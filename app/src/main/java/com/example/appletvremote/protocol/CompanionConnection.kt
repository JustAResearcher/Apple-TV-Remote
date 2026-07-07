package com.example.appletvremote.protocol

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

enum class CompanionFrameType(val value: Int) {
    PS_START(3),
    PS_NEXT(4),
    PV_START(5),
    PV_NEXT(6),
    U_OPACK(7),
    E_OPACK(8),
    P_OPACK(9)
}

data class CompanionFrame(val type: CompanionFrameType, val payload: ByteArray)

class CompanionConnection {
    companion object {
        private const val CONNECT_TIMEOUT = 10_000
        private const val READ_TIMEOUT = 30_000
        private const val AUTH_TAG_LENGTH = 16
    }

    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null
    private var cipher: CompanionCipher? = null

    suspend fun connect(host: String, port: Int) = withContext(Dispatchers.IO) {
        val sock = Socket()
        sock.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT)
        sock.soTimeout = READ_TIMEOUT
        sock.tcpNoDelay = true
        sock.keepAlive = true
        socket = sock
        inputStream = sock.getInputStream()
        outputStream = sock.getOutputStream()
    }

    fun enableEncryption(outputKey: ByteArray, inputKey: ByteArray) {
        cipher = CompanionCipher(outputKey, inputKey)
    }

    fun disconnect() {
        try {
            socket?.close()
        } catch (_: Exception) {
        }
        socket = null
        inputStream = null
        outputStream = null
        cipher = null
    }

    suspend fun send(type: CompanionFrameType, payload: ByteArray) = withContext(Dispatchers.IO) {
        val os = outputStream ?: throw IllegalStateException("Not connected")
        var wirePayload = payload
        val encrypted = cipher
        val payloadLength = if (encrypted != null && payload.isNotEmpty()) {
            payload.size + AUTH_TAG_LENGTH
        } else {
            payload.size
        }
        val header = byteArrayOf(
            type.value.toByte(),
            ((payloadLength shr 16) and 0xFF).toByte(),
            ((payloadLength shr 8) and 0xFF).toByte(),
            (payloadLength and 0xFF).toByte()
        )
        if (encrypted != null && payload.isNotEmpty()) {
            wirePayload = encrypted.encrypt(payload, header)
        }
        os.write(header)
        os.write(wirePayload)
        os.flush()
    }

    suspend fun receive(): CompanionFrame = withContext(Dispatchers.IO) {
        val ins = inputStream ?: throw IllegalStateException("Not connected")
        val header = readExact(ins, 4)
        val typeValue = header[0].toInt() and 0xFF
        val payloadLength = ((header[1].toInt() and 0xFF) shl 16) or
                ((header[2].toInt() and 0xFF) shl 8) or
                (header[3].toInt() and 0xFF)
        val encryptedPayload = readExact(ins, payloadLength)
        val payload = cipher?.decrypt(encryptedPayload, header) ?: encryptedPayload
        CompanionFrame(
            type = CompanionFrameType.values().firstOrNull { it.value == typeValue }
                ?: throw IllegalStateException("Unsupported Companion frame type: $typeValue"),
            payload = payload
        )
    }

    private fun readExact(input: InputStream, length: Int): ByteArray {
        val buffer = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val read = input.read(buffer, offset, length - offset)
            if (read < 0) throw java.io.IOException("Connection closed (read $offset/$length)")
            offset += read
        }
        return buffer
    }
}
