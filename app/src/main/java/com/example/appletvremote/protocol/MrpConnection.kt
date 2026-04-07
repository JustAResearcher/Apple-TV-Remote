package com.example.appletvremote.protocol

import android.util.Log
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Manages the TLS connection to Apple TV for MRP protocol communication.
 *
 * Apple TV requires TLS for MRP. The Apple TV uses a self-signed certificate,
 * so we disable certificate verification (same as all other MRP clients).
 *
 * Message framing (unencrypted, i.e. before pair-verify):
 *   [4-byte big-endian length] [protobuf ProtocolMessage]
 *
 * Message framing (encrypted, after pair-verify):
 *   [2-byte LE length (AAD)] [encrypted payload + 16-byte tag]
 */
class MrpConnection {
    companion object {
        private const val TAG = "MrpConnection"
        private const val CONNECT_TIMEOUT = 10_000
        private const val READ_TIMEOUT = 30_000
    }

    private var socket: Socket? = null
    private var sslSocket: SSLSocket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null
    var cipher: MrpCipher? = null
    var isConnected = false
        private set

    suspend fun connect(host: String, port: Int) = withContext(Dispatchers.IO) {
        try {
            // Create a trust manager that accepts all certificates (Apple TV uses self-signed)
            val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            })

            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, trustAllCerts, SecureRandom())

            // First connect a plain TCP socket
            val plainSocket = Socket()
            plainSocket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT)
            Log.d(TAG, "TCP connected to $host:$port, upgrading to TLS...")

            // Upgrade to TLS
            val ssl = sslContext.socketFactory.createSocket(
                plainSocket, host, port, true
            ) as SSLSocket

            // Disable hostname verification
            ssl.soTimeout = READ_TIMEOUT

            // Start TLS handshake
            ssl.startHandshake()
            Log.d(TAG, "TLS handshake complete with $host:$port")

            socket = plainSocket
            sslSocket = ssl
            inputStream = ssl.inputStream
            outputStream = ssl.outputStream
            isConnected = true
            Log.d(TAG, "Connected (TLS) to $host:$port")
        } catch (e: Exception) {
            Log.e(TAG, "Connection failed: ${e.message}")
            throw e
        }
    }

    fun disconnect() {
        try {
            isConnected = false
            sslSocket?.close()
            socket?.close()
        } catch (_: Exception) {
        }
        socket = null
        sslSocket = null
        inputStream = null
        outputStream = null
        cipher = null
    }

    /**
     * Send a protobuf-encoded ProtocolMessage.
     * Over TLS (before pair-verify): varint length + protobuf
     * After pair-verify: ChaCha20 encrypted frames
     */
    suspend fun sendMessage(protobufData: ByteArray) = withContext(Dispatchers.IO) {
        val os = outputStream ?: throw IllegalStateException("Not connected")

        val encCipher = cipher
        if (encCipher != null) {
            val encrypted = encCipher.encrypt(protobufData)
            os.write(encrypted)
        } else {
            // Varint length prefix + protobuf payload
            os.write(encodeVarint(protobufData.size))
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
            encCipher.decrypt(header + encrypted)
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
