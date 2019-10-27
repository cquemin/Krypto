package com.island.yoshiz.mpp.krypto.common.random

/**
 * Secure random number generator
 */
expect class SecureRandomGenerator() {

    /**
     * Generate a secure random array of bytes. The returning array will of length [lengthBytes]
     */
    fun generateBytes(lengthBytes: Int): ByteArray
}
