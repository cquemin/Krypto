package com.island.yoshiz.mpp.krypto.aes.model.config

internal enum class AesBlockMode(
        val ivLengthBytes: Int,
        val expectPadding: Boolean,
        val secureRequireIv: Boolean
) {

    /**
     * Cipher Block Chaining
     * Recommended for any length of data
     * Recommended to use
     */
    CBC(16, true, true),

    /**
     * Counter Mode, does not need Padding as it turns block cipher into a stream cipher
     * Recommended to use
     */
    CTR(16, false, false),

    /**
     * Galois/Counter Mode. Encryption with Authentication Message
     * Recommended if abvailable
     */
    GCM(12, false, false)
}