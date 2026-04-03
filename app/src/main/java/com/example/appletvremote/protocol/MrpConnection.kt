package com.example.appletvremote.protocol

import android.util.Log
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Manages the TCP connection to Apple TV for MRP protocol communication.
 * Handles message framing (1-byte type + 3-byte length + protobuf payload)
 * and optional encryption after pair-verify completes.
 */
class MrpConnection {
    companion object {
        private const val TAG = "MrpConnection"
        private const val CONNECT_TIMEOUT = 10_000
        private const val READ_TIMEOUT = 30_000
    }

    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null
    var cipher: MrpCipher? = null
    var isConnected = false
        private set

    suspend fun connect(host: String, port: Int) = withContext(Dispatchers.IO) {
        try {
            val sock = Socket()
            sock.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT)
            sock.soTimeout = READ_TIMEOUT
            socket = sock
            inputStream = sock.getInputStream()
            outputStream = sock.getOutputStream()
            isConnected = true
            Log.d(TAG, "Connected to $host:$port")
        } catch (e: Exception) {
            Log.e(TAG, "Connection failed: ${e.message}")
            throw e
        }
    }

    fun disconnect() {
        try {
            isConnected = false
            socket?.close()
        } catch (_: Exception) {
        }
        socket = null
        inputStream = null
        outputStream = null
        cipher = null
    }

    /**
     * Send a protobuf-encoded ProtocolMessage.
     * If encryption is active, the entire frame (type + length + payload) is encrypted.
     */
    suspend fun sendMessage(protobufData: ByteArray) = withContext(Dispatchers.IO) {
        val os = outputStream ?: throw IllegalStateException("Not connected")

        // Build raw MRP frame: [type(1)] [length(3 big-endian)] [payload]
        // Type byte is first byte of protobuf (contains field 1 tag)
        val frame = ByteArray(4 + protobufData.size)
        // For MRP, the 4-byte header is just the big-endian length of the protobuf
        val length = protobufData.size
        frame[0] = ((length shr 24) and 0xFF).toByte()
        frame[1] = ((length shr 16) and 0xFF).toByte()
        frame[2] = ((length shr 8) and 0xFF).toByte()
        frame[3] = (length and 0xFF).toByte()

        val encCipher = cipher
        if (encCipher != null) {
            val encrypted = encCipher.encrypt(frame)
            os.write(encrypted)
        } else {
            os.write(frame)
            os.write(protobufData)
        }
        os.flush()
    }

    /**
     * Send raw bytes without framing (used during pairing before message framing is established).
     */
    suspend fun sendRaw(data: ByteArray) = withContext(Dispatchers.IO) {
        val os = outputStream ?: throw IllegalStateException("Not connected")
        os.write(data)
        os.flush()
    }

    /**
     * Receive a protobuf ProtocolMessage.
     * Handles both encrypted and unencrypted frames.
     */
    suspend fun receiveMessage(): ByteArray = withContext(Dispatchers.IO) {
        val ins = inputStream ?: throw IllegalStateException("Not connected")

        val encCipher = cipher
        if (encCipher != null) {
            // Read 2-byte encrypted header (AAD)
            val header = readExact(ins, 2)
            val payloadLength = encCipher.decryptedLength(header)
            // Read encrypted payload + 16-byte auth tag
            val encrypted = readExact(ins, payloadLength + 16)
            val frame = encCipher.decrypt(header + encrypted)
            // frame = [4-byte header] [protobuf]
            if (frame.size > 4) {
                frame.copyOfRange(4, frame.size)
            } else {
                ByteArray(0)
            }
        } else {
            // Read 4-byte header (big-endian length)
            val header = readExact(ins, 4)
            val length = ((header[0].toInt() and 0xFF) shl 24) or
                    ((header[1].toInt() and 0xFF) shl 16) or
                    ((header[2].toInt() and 0xFF) shl 8) or
                    (header[3].toInt() and 0xFF)

            if (length <= 0 || length > 1_000_000) {
                throw IllegalStateException("Invalid message length: $length")
            }
            readExact(ins, length)
        }
    }

    /**
     * Read raw bytes (used during pairing).
     */
    suspend fun receiveRaw(length: Int): ByteArray = withContext(Dispatchers.IO) {
        val ins = inputStream ?: throw IllegalStateException("Not connected")
        readExact(ins, length)
    }

    private fun readExact(input: InputStream, length: Int): ByteArray {
        val buffer = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val read = input.read(buffer, offset, length - offset)
            if (read < 0) throw java.io.IOException("Connection closed")
            offset += read
        }
        return buffer
    }
}
