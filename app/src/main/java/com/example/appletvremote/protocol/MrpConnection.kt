package com.example.appletvremote.protocol

import android.util.Log
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Manages the TCP connection to Apple TV for MRP protocol communication.
 *
 * MRP message framing (unencrypted):
 *   [varint length] [protobuf ProtocolMessage]
 *
 * MRP message framing (encrypted, after pair-verify):
 *   [2-byte LE length (AAD)] [encrypted(varint length + protobuf) + 16-byte tag]
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
            sock.tcpNoDelay = true
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
     * Send a protobuf-encoded ProtocolMessage with varint length framing.
     */
    suspend fun sendMessage(protobufData: ByteArray) = withContext(Dispatchers.IO) {
        val os = outputStream ?: throw IllegalStateException("Not connected")

        val encCipher = cipher
        if (encCipher != null) {
            // Encrypted: build inner frame (varint + protobuf), then encrypt
            val innerFrame = encodeVarint(protobufData.size) + protobufData
            val encrypted = encCipher.encrypt(innerFrame)
            os.write(encrypted)
        } else {
            // Unencrypted: varint length prefix + protobuf payload
            val varint = encodeVarint(protobufData.size)
            os.write(varint)
            os.write(protobufData)
        }
        os.flush()
        Log.d(TAG, "Sent message: ${protobufData.size} bytes")
    }

    /**
     * Receive a protobuf ProtocolMessage.
     */
    suspend fun receiveMessage(): ByteArray = withContext(Dispatchers.IO) {
        val ins = inputStream ?: throw IllegalStateException("Not connected")

        val encCipher = cipher
        if (encCipher != null) {
            // Read 2-byte encrypted header (AAD = plaintext length LE)
            val header = readExact(ins, 2)
            val payloadLength = encCipher.decryptedLength(header)
            // Read encrypted payload + 16-byte auth tag
            val encrypted = readExact(ins, payloadLength + 16)
            val decrypted = encCipher.decrypt(header + encrypted)
            // Decrypted contains: varint length + protobuf
            val (msgLen, offset) = readVarintFromArray(decrypted, 0)
            decrypted.copyOfRange(offset, offset + msgLen.toInt())
        } else {
            // Read varint length prefix
            val length = readVarint(ins)
            if (length <= 0 || length > 1_000_000) {
                throw IllegalStateException("Invalid message length: $length")
            }
            Log.d(TAG, "Receiving message: $length bytes")
            readExact(ins, length.toInt())
        }
    }

    private fun encodeVarint(value: Int): ByteArray {
        val result = mutableListOf<Byte>()
        var v = value
        while (v > 0x7F) {
            result.add(((v and 0x7F) or 0x80).toByte())
            v = v ushr 7
        }
        result.add((v and 0x7F).toByte())
        return result.toByteArray()
    }

    private fun readVarint(input: InputStream): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = input.read()
            if (b < 0) throw java.io.IOException("Connection closed while reading varint")
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 35) throw IllegalStateException("Varint too long")
        }
        return result
    }

    private fun readVarintFromArray(data: ByteArray, startOffset: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var offset = startOffset
        while (offset < data.size) {
            val b = data[offset].toInt() and 0xFF
            result = result or ((b.toLong() and 0x7F) shl shift)
            offset++
            if (b and 0x80 == 0) break
            shift += 7
        }
        return result to offset
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
