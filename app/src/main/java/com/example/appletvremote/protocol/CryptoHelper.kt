package com.example.appletvremote.protocol

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.signers.Ed25519Signer

object CryptoHelper {

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
        return chaCha20Poly1305(true, key, nonce, plaintext, aad)
    }

    fun chaCha20Poly1305Decrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray? = null): ByteArray {
        return chaCha20Poly1305(false, key, nonce, ciphertext, aad)
    }

    private fun chaCha20Poly1305(
        forEncryption: Boolean,
        key: ByteArray,
        nonce: ByteArray,
        input: ByteArray,
        aad: ByteArray?
    ): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(forEncryption, AEADParameters(KeyParameter(key), 128, nonce, aad))
        val output = ByteArray(cipher.getOutputSize(input.size))
        val processed = cipher.processBytes(input, 0, input.size, output, 0)
        val finalSize = cipher.doFinal(output, processed)
        return output.copyOf(processed + finalSize)
    }

    fun buildNonce(counter: Long): ByteArray {
        val nonce = ByteArray(12)
        for (i in 0..7) {
            nonce[4 + i] = ((counter shr (i * 8)) and 0xFF).toByte()
        }
        return nonce
    }
}

/**
 * ChaCha20-Poly1305 cipher matching pyatv's Chacha20Cipher8byteNonce.
 * No AAD, no 2-byte length header. Just encrypt/decrypt with counter-based nonce.
 * The varint framing in MrpConnection handles message boundaries.
 */
class MrpCipher(private val outputKey: ByteArray, private val inputKey: ByteArray) {
    private var outCounter: Long = 0
    private var inCounter: Long = 0

    fun encrypt(data: ByteArray): ByteArray {
        val nonce = CryptoHelper.buildNonce(outCounter++)
        return CryptoHelper.chaCha20Poly1305Encrypt(outputKey, nonce, data)
    }

    fun decrypt(data: ByteArray): ByteArray {
        val nonce = CryptoHelper.buildNonce(inCounter++)
        return CryptoHelper.chaCha20Poly1305Decrypt(inputKey, nonce, data)
    }
}
