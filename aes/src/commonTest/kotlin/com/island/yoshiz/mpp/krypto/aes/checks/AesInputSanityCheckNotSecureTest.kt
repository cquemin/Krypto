package com.island.yoshiz.mpp.krypto.aes.checks

import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CBC
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes256
import com.island.yoshiz.mpp.krypto.aes.model.keys.IV
import com.island.yoshiz.mpp.krypto.aes.random.AesSecureRandom
import kotlin.test.*

class AesInputSanityCheckNotSecureTest {
    private val aesMode = CBC

    private lateinit var checker: AesInputSanityCheckNotSecure

    @BeforeTest
    fun setup() {
        checker = AesInputSanityCheckNotSecure(aesMode)
    }

    @Test
    fun testValidateIv_givenIvIsZeroed_thenAesInvalidNoException() {
        val iv = IV(aesMode.ivLengthBytes)

        checker.validateIv(iv)
    }

    @Test
    fun testValidateIv_givenIvIsNotZeroed_thenNoException() {
        val iv = AesSecureRandom(Aes256, aesMode).generateIv()

        checker.validateIv(iv)
    }
}