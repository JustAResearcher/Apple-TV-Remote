package com.example.appletvremote.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SrpClientTest {

    @Test
    fun `pair setup proof matches srptools reference vector`() {
        val privateSeed = hexToBytes(
            "0102030405060708090a0b0c0d0e0f10" +
                "1112131415161718191a1b1c1d1e1f20"
        )
        val salt = hexToBytes("101112131415161718191a1b1c1d1e1f")
        val serverPublicKey = hexToBytes(
            "4f18fa05acd54145a3f88efa7e3584f80e8482f50032da01278c48be9d801114" +
                "c10ca3feb41403f50909a084840617bc272a17155c6786ee5de8c09ea92960965" +
                "258dc4e8cfcd1fd77a830c6f2568b0bcb7fd3d535212b6bdb98a0d078886e76d" +
                "e57718e5e9799b24ba4aa8152ff7049dfdd61bf96dc5ab64a52614faf3fb8009c" +
                "51e0992b78976682cf847074a31418db4e618892bb28d33446e22c635b66a477b" +
                "d6fe9ff8648f6915ae7bb71d68dd06d7cc1d1e45927aa866df2340224b15ee9b" +
                "2fb973362b752219470524862c747c98f74d335435e84bfd5877fe94fd4bd8c6d" +
                "8e3215efc99d799fc653d17c86125adda8c823f8fc7b2c0f5df5f8314315fb4d7" +
                "d2c91a4accfc3d4a6d637518933076a3bbf4f3a3c5156a6e29efb4feca34f4a37" +
                "0cfd61f86c35946193a233ffdd4c87a801c74ff8d6ab93092455e4dc03d4374a5" +
                "9e3def0d37b231b41fb6c30404ec0f4cbb998d49661f987c795f29433eb78f62d" +
                "ff492cf7a376d36c9b57718286fefaacb4ff4b5f5551546a62b58b59"
        )
        val client = SrpClient()

        val publicKey = client.generateCredentials(privateSeed)
        val proof = client.processChallenge("Pair-Setup", "1234", salt, serverPublicKey)

        assertArrayEquals(
            hexToBytes(
                "bc0e7cf5dc3babf67dcedbb3b140aacc6cac43f4336b43bbd5de48d6ea7c8eda" +
                    "66924e354255225bccad9debe21182e6bb050f3ff3e6cfbb62c229379968c70ca" +
                    "436ad649a0b051373184215eef046f6f1f2256838f958581f6c7b2b85fa4afe326" +
                    "a0e8a951d4489305331aff88a136fd8d108bcc95fceb7e557c889c828bd23fb070" +
                    "2f053e1ca6470fb3c76bce4843fc005c7ea675740f8550212656cfc8919d9db805" +
                    "a434a68229e0d9dfe43fc16dc680a5ce74b77cf374353b05759bc1da3a9dabde30" +
                    "a4209381c87ca83d9483abdf66b86f9b1cbda9ad82c62712b87ce6fb7069b8fc8d" +
                    "f344261821a06d0dc5106af76d4245f3f7737a94dbc484b415555dc401842d3011" +
                    "204553ba9f611b02bc38de26eba1a76bf8350205a62c436ba1c3c7c69d59318bd" +
                    "107fd1c1f5d846b3142e85a5d49e522655e020ed1bfe1e186cf923bf328f0b9b" +
                    "4c6a8aa3266ed9125bb98d63827110713be7803122ee4603c54ea31863ce4b10a" +
                    "ff31f9073cf63b94733b4f066e72d4ec35687047d5d0db160"
            ),
            publicKey
        )
        assertArrayEquals(
            hexToBytes(
                "a9acaf68af11afa77633bdf95b82f778d9d5174c663d6e02a735744da8549b67" +
                    "1025d060c321c187b9d4221e8576b272258cba8655078476e1195ca0763fc5b1"
            ),
            proof
        )
        assertArrayEquals(
            hexToBytes(
                "fd3c073222caa2131b2d3e371a6a77ff0cbab949c9106f431bd7cf3ed9234a98" +
                    "919284d91434e926ce5afeabd203cef0ca72e4b64cb85496c5057b1494103f95"
            ),
            client.getSessionKey()
        )
        assertTrue(
            client.verifyServerProof(
                hexToBytes(
                    "23072e0ad4200e7870a6f7d6f47ce517650a0c3496599fb78742b84ac519db52" +
                        "4b57b1e9bfb8e70a58ad597488ce1f7120ee5a2f9dee57ecc0d1b7bfaccac0cb"
                )
            )
        )
    }

    private fun hexToBytes(value: String): ByteArray {
        return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
