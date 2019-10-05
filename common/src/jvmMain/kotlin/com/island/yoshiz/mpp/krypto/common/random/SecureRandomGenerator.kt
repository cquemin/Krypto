package com.island.yoshiz.mpp.krypto.common.random

import com.island.yoshiz.mpp.krypto.common.model.exceptions.SecureRandomException
import java.security.SecureRandom

/**
 * Secure random number generator
 */
actual class SecureRandomGenerator actual constructor() {

    /**
     * Generate a secure random array of bytes. The returning array will of length [lengthBytes]
     */
    actual fun generateBytes(lengthBytes: Int): ByteArray {
        try {
            val secureRandom = SecureRandom.getInstance("SHA1PRNG")
            val key = ByteArray(lengthBytes)
            secureRandom.nextBytes(key)

            return key
        } catch (exception: Throwable) {
            throw SecureRandomException(cause = exception)
        }
    }
}