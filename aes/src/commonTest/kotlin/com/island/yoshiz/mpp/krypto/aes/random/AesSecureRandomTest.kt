package com.island.yoshiz.mpp.krypto.aes.random

import com.island.yoshiz.mpp.krypto.aes.checks.AesInputSanityCheck
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CBC
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes256
import com.island.yoshiz.mpp.krypto.common.random.SecureRandomGenerator
import kotlin.test.*

class AesSecureRandomTest {
    private lateinit var generator: AesSecureRandom

    private var secureRandomGenerator = SecureRandomGenerator()
    private val checks = AesInputSanityCheck(CBC)

    @BeforeTest
    fun setup() {
        generator = AesSecureRandom(Aes256, CBC, secureRandomGenerator)
    }

    @Test
    fun testGenerateAesKeyAndIv_thenSuccessfulKeyIvGeneration() {
        val key = generator.generateAesKeyAndIv()

        // should not raise any exception
        checks.validateAesKey(key.aesKey)
        checks.validateIv(key.iv)

        assertEquals(Aes256.lengthBytes, key.aesKey.size)
        assertEquals(CBC.ivLengthBytes, key.iv.size)
    }

    @Test
    fun testGenerateAesKey_thenSuccessfulKeyAndIvGeneration() {
        val key = generator.generateAesKey()
        val iv = generator.generateIv()

        // should not raise any exception
        checks.validateAesKey(key)
        checks.validateIv(iv)

        assertEquals(Aes256.lengthBytes, key.material.size)
        assertEquals(CBC.ivLengthBytes, iv.size)
    }
}
