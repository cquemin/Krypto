package com.island.yoshiz.mpp.krypto.common.random

import kotlin.test.*

class SecureRandomTest {

    private lateinit var generator: SecureRandomGenerator

    @BeforeTest
    fun setup() {
        generator = SecureRandomGenerator()
    }

    @Test
    fun testGenerationNotAllZeroes() {
        val result = generator.generateBytes(16)
        assertFalse { result.all { it == 0.toByte() } }
    }

    @Test
    fun testGenerationCorrectOutputSize() {
        val result = generator.generateBytes(16)
        assertEquals(16, result.size)
    }
}

