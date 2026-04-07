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
     * Send a protobuf-encoded ProtocolMessage with 4-byte big-endian length framing.
     */
    suspend fun sendMessage(protobufData: ByteArray) = withContext(Dispatchers.IO) {
        val os = outputStream ?: throw IllegalStateException("Not connected")

        val encCipher = cipher
        if (encCipher != null) {
            // Encrypted: build inner frame (4-byte header + protobuf), then encrypt
            val header = ByteArray(4)
            val length = protobufData.size
            header[0] = ((length shr 24) and 0xFF).toByte()
            header[1] = ((length shr 16) and 0xFF).toByte()
            header[2] = ((length shr 8) and 0xFF).toByte()
            header[3] = (length and 0xFF).toByte()
            val innerFrame = header + protobufData
            val encrypted = encCipher.encrypt(innerFrame)
            os.write(encrypted)
        } else {
            // Unencrypted: 4-byte big-endian length + protobuf payload
            val header = ByteArray(4)
            val length = protobufData.size
            header[0] = ((length shr 24) and 0xFF).toByte()
            header[1] = ((length shr 16) and 0xFF).toByte()
            header[2] = ((length shr 8) and 0xFF).toByte()
            header[3] = (length and 0xFF).toByte()
            os.write(header)
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
            // Decrypted contains: 4-byte header + protobuf
            if (decrypted.size > 4) {
                decrypted.copyOfRange(4, decrypted.size)
            } else {
                ByteArray(0)
            }
        } else {
            // Read 4-byte big-endian length header
            val header = readExact(ins, 4)
            val length = ((header[0].toInt() and 0xFF) shl 24) or
                    ((header[1].toInt() and 0xFF) shl 16) or
                    ((header[2].toInt() and 0xFF) shl 8) or
                    (header[3].toInt() and 0xFF)

            if (length <= 0 || length > 1_000_000) {
                throw IllegalStateException("Invalid message length: $length")
            }
            Log.d(TAG, "Receiving message: $length bytes")
            readExact(ins, length)
        }
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
