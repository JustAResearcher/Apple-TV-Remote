package com.example.appletvremote.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CryptoHelperTest {

    @Test
    fun `chacha20 poly1305 decrypts encrypted payload`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = CryptoHelper.buildNonce(0)
        val plaintext = "hello apple tv".toByteArray()

        val encrypted = CryptoHelper.chaCha20Poly1305Encrypt(key, nonce, plaintext)
        val decrypted = CryptoHelper.chaCha20Poly1305Decrypt(key, nonce, encrypted)

        assertFalse(plaintext.contentEquals(encrypted))
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun `mrp cipher uses incrementing counter nonces`() {
        val key = ByteArray(32) { (it + 1).toByte() }
        val sender = MrpCipher(key, key)
        val receiver = MrpCipher(key, key)
        val first = "first".toByteArray()
        val second = "second".toByteArray()

        val encryptedFirst = sender.encrypt(first)
        val encryptedSecond = sender.encrypt(second)

        assertFalse(encryptedFirst.contentEquals(encryptedSecond))
        assertArrayEquals(first, receiver.decrypt(encryptedFirst))
        assertArrayEquals(second, receiver.decrypt(encryptedSecond))
    }

    @Test
    fun `generated nonce is eight byte little endian counter with four byte prefix`() {
        val nonce = CryptoHelper.buildNonce(0x0102030405060708L)

        assertArrayEquals(
            byteArrayOf(
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x07,
                0x06,
                0x05,
                0x04,
                0x03,
                0x02,
                0x01
            ),
            nonce
        )
        assertTrue(nonce.size == 12)
    }

    @Test
    fun `companion nonce is twelve byte little endian counter`() {
        val nonce = CryptoHelper.buildNonce12(0x0102030405060708L)

        assertArrayEquals(
            byteArrayOf(
                0x08,
                0x07,
                0x06,
                0x05,
                0x04,
                0x03,
                0x02,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00
            ),
            nonce
        )
        assertTrue(nonce.size == 12)
    }
}
