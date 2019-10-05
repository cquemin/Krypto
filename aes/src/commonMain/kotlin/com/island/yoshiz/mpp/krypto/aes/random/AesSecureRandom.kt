package com.island.yoshiz.mpp.krypto.aes.random

import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKey
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKeyIv
import com.island.yoshiz.mpp.krypto.aes.model.keys.IV
import com.island.yoshiz.mpp.krypto.common.random.SecureRandomGenerator

/**
 * Provides methods to generate securely AES key length buffer and IV buffers
 */
internal class AesSecureRandom(
        private val keysLength: AesKeysLength,
        private val blockMode: AesBlockMode,
        private val generator: SecureRandomGenerator
) {

    internal constructor(
            keysLength: AesKeysLength,
            blockMode: AesBlockMode
    ) : this(keysLength, blockMode, SecureRandomGenerator())

    /**
     * @return a new instance of a [AesKeyIv] where the key and iv are
     * generated using a secure random generator
     */
    fun generateAesKeyAndIv(): AesKeyIv {
        val key = generateAesKey()
        val iv = generateIv()

        return AesKeyIv(iv, key)
    }

    /**
     * @return an [IV] of the length specified in [blockMode]
     */
    fun generateAesKey() = AesKey(generator.generateBytes(keysLength.lengthBytes))

    /**
     * @return an [IV] of the length specified in [blockMode]
     */
    fun generateIv() = IV(generator.generateBytes(blockMode.ivLengthBytes))
}