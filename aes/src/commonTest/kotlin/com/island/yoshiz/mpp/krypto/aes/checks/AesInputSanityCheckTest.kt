package com.island.yoshiz.mpp.krypto.aes.checks

import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CBC
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes256
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesInvalidIvException
import com.island.yoshiz.mpp.krypto.aes.model.keys.IV
import com.island.yoshiz.mpp.krypto.aes.random.AesSecureRandom
import kotlin.test.*

class AesInputSanityCheckTest {
    private val aesMode = CBC

    private lateinit var checker: AesInputSanityCheck

    @BeforeTest
    fun setup() {
        checker = AesInputSanityCheck(aesMode)
    }

    @Test
    fun testValidateIv_givenIvIsZeroed_thenAesInvalidAesInvalidIvException() {
        val iv = IV(aesMode.ivLengthBytes)

        assertFailsWith(AesInvalidIvException::class) {
            checker.validateIv(iv)
        }
    }

    @Test
    fun testValidateIv_givenIvIsNotZeroed_thenNoException() {
        val iv = AesSecureRandom(Aes256, aesMode).generateIv()

        checker.validateIv(iv)
    }
}