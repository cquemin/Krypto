package com.island.yoshiz.mpp.krypto.common.random

import com.island.yoshiz.mpp.krypto.common.model.exceptions.SecureRandomException
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import platform.Security.SecRandomCopyBytes
import platform.Security.errSecSuccess
import platform.Security.kSecRandomDefault
import platform.posix.memcpy

/**
 * Secure random number generator
 */
actual class SecureRandomGenerator actual constructor() {

    /**
     * Generate a secure random array of bytes. The returning array will of length [lengthBytes]
     */
    actual fun generateBytes(lengthBytes: Int): ByteArray = memScoped {
        val buffer = allocArray<ByteVar>(lengthBytes)

        val status = SecRandomCopyBytes(
                kSecRandomDefault,
                lengthBytes.convert(),
                buffer
        )

        if (status == errSecSuccess) {
            val result = ByteArray(lengthBytes)
            memcpy(result.refTo(0), buffer, lengthBytes.convert())
            return@memScoped result
        } else {
            throw SecureRandomException(
                    "An error has occurred: $status" +
                            " while trying to generate $lengthBytes bytes"
            )
        }
    }
}