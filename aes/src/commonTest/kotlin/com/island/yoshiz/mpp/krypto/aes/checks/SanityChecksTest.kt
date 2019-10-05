package com.island.yoshiz.mpp.krypto.aes.checks

import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CBC
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CTR
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.GCM
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes256
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesInvalidIvException
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesInvalidKeyException
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesNotImplementedException
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKey
import com.island.yoshiz.mpp.krypto.aes.model.keys.IV
import com.island.yoshiz.mpp.krypto.aes.random.AesSecureRandom
import com.island.yoshiz.mpp.krypto.common.random.SecureRandomGenerator
import kotlin.test.*

class SanityChecksTest {
    private val aesKeysLength = Aes256
    private val aesMode = CBC

    private lateinit var checker: SanityChecksForTest

    private val secureRandom = AesSecureRandom(aesKeysLength, aesMode)

    @BeforeTest
    fun setup() {
        checker = SanityChecksForTest(aesMode)
    }

    @Test
    fun testConstructor_givenCTRMode_thenAesNotImplementedException() {
        assertFailsWith(AesNotImplementedException::class) {
            SanityChecksForTest(CTR)
        }
    }

    @Test
    fun testConstructor_givenGCMMode_thenAesNotImplementedException() {
        assertFailsWith(AesNotImplementedException::class) {
            SanityChecksForTest(GCM)
        }
    }

    @Test
    fun testValidateAesKey_givenAesKeyIsCorrect_thenNoException() {
        val key = secureRandom.generateAesKey()

        checker.validateAesKey(key)
    }

    @Test
    fun testValidateAesKey_givenAesKeyHasWrongLength_thenAesInvalidKeyException() {
        val keyMaterial = SecureRandomGenerator().generateBytes(3)

        assertFailsWith(AesInvalidKeyException::class) {
            checker.validateAesKey(AesKey(keyMaterial))
        }
    }

    @Test
    fun testValidateAesKey_givenAesKeyIsZeroed_thenAesInvalidKeyException() {
        val keyMaterial = ByteArray(aesKeysLength.lengthBytes)

        assertFailsWith(AesInvalidKeyException::class) {
            checker.validateAesKey(AesKey(keyMaterial))
        }
    }

    @Test
    fun testValidateIv_givenIvIsCorrect_thenNoException() {
        val iv = secureRandom.generateIv()

        checker.validateIv(iv)
    }

    @Test
    fun testValidateIv_givenIvIsWrongLength_thenAesInvalidIvException() {
        val iv = IV(3)

        assertFailsWith(AesInvalidIvException::class) {
            checker.validateIv(iv)
        }
    }

    private class SanityChecksForTest(mode: AesBlockMode) : AesSanityChecks(mode) {
        override fun onIvNotSecureToUse() {
        }
    }
}