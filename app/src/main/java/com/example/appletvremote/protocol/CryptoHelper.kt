package com.example.appletvremote.protocol

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object CryptoHelper {

    init {
        // Android ships a stripped-down BouncyCastle. Remove it and insert the full one
        // so ChaCha20-Poly1305 and other algorithms are available.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    // --- Ed25519 ---

    data class Ed25519KeyPair(val privateKey: ByteArray, val publicKey: ByteArray)

    fun generateEd25519KeyPair(): Ed25519KeyPair {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(java.security.SecureRandom()))
        val pair = gen.generateKeyPair()
        val priv = (pair.private as Ed25519PrivateKeyParameters).encoded
        val pub = (pair.public as Ed25519PublicKeyParameters).encoded
        return Ed25519KeyPair(priv, pub)
    }

    fun ed25519Sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKey, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }

    // --- X25519 ---

    data class X25519KeyPair(val privateKey: ByteArray, val publicKey: ByteArray)

    fun generateX25519KeyPair(): X25519KeyPair {
        val gen = X25519KeyPairGenerator()
        gen.init(X25519KeyGenerationParameters(java.security.SecureRandom()))
        val pair = gen.generateKeyPair()
        val priv = (pair.private as X25519PrivateKeyParameters).encoded
        val pub = (pair.public as X25519PublicKeyParameters).encoded
        return X25519KeyPair(priv, pub)
    }

    fun x25519SharedSecret(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(privateKey, 0))
        val shared = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(peerPublicKey, 0), shared, 0)
        return shared
    }

    // --- HKDF-SHA-512 ---

    fun hkdfSha512(ikm: ByteArray, salt: String, info: String, length: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(org.bouncycastle.crypto.digests.SHA512Digest())
        hkdf.init(HKDFParameters(ikm, salt.toByteArray(), info.toByteArray()))
        val out = ByteArray(length)
        hkdf.generateBytes(out, 0, length)
        return out
    }

    // --- ChaCha20-Poly1305 ---

    fun chaCha20Poly1305Encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305", "BC")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    fun chaCha20Poly1305Decrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray? = null): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305", "BC")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    /**
     * Build a 12-byte nonce from an 8-byte little-endian counter.
     */
    fun buildNonce(counter: Long): ByteArray {
        val nonce = ByteArray(12)
        // First 4 bytes are zeros, last 8 bytes are the counter in little-endian
        for (i in 0..7) {
            nonce[4 + i] = ((counter shr (i * 8)) and 0xFF).toByte()
        }
        return nonce
    }
}

/**
 * Handles encrypted message framing for MRP after pair-verify completes.
 * Each encrypted frame: 2-byte LE length (AAD) + encrypted data + 16-byte auth tag
 */
class MrpCipher(private val readKey: ByteArray, private val writeKey: ByteArray) {
    private var readCounter: Long = 0
    private var writeCounter: Long = 0

    fun encrypt(data: ByteArray): ByteArray {
        val nonce = CryptoHelper.buildNonce(writeCounter++)
        val aad = ByteArray(2)
        aad[0] = (data.size and 0xFF).toByte()
        aad[1] = ((data.size shr 8) and 0xFF).toByte()

        val encrypted = CryptoHelper.chaCha20Poly1305Encrypt(writeKey, nonce, data, aad)
        return aad + encrypted
    }

    fun decrypt(data: ByteArray): ByteArray {
        val nonce = CryptoHelper.buildNonce(readCounter++)
        val aad = data.copyOfRange(0, 2)
        val length = (aad[0].toInt() and 0xFF) or ((aad[1].toInt() and 0xFF) shl 8)
        val ciphertext = data.copyOfRange(2, 2 + length + 16) // ciphertext + tag

        return CryptoHelper.chaCha20Poly1305Decrypt(readKey, nonce, ciphertext, aad)
    }

    fun expectedEncryptedLength(data: ByteArray): Int {
        return 2 + data.size + 16
    }

    fun decryptedLength(header: ByteArray): Int {
        return (header[0].toInt() and 0xFF) or ((header[1].toInt() and 0xFF) shl 8)
    }
}
