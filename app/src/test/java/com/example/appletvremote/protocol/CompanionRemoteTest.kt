package com.example.appletvremote.protocol

import org.junit.Assert.assertEquals
import org.junit.Test

class CompanionRemoteTest {

    @Test
    fun `rapport identifier is stable for saved client id`() {
        val clientId = "123E4567-E89B-12D3-A456-426614174000"

        assertEquals("123e4567e89b", CompanionRemote.rapportIdentifier(clientId))
        assertEquals(
            CompanionRemote.rapportIdentifier(clientId),
            CompanionRemote.rapportIdentifier(clientId)
        )
    }
}
