package com.island.yoshiz.mpp.krypto.aes.checks

import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CTR
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.GCM
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesInvalidIvException
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesInvalidKeyException
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesNotImplementedException
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKey
import com.island.yoshiz.mpp.krypto.aes.model.keys.IV
import com.island.yoshiz.mpp.krypto.aes.model.keys.all

/**
 * This class is responsible to verify if the aes key, IV the data, the chosen mode conform to
 * a possible and safe usage.
 * In particular it checks:
 * - if the AES key length is among 128, 192, 256 bits, if not a [AesInvalidKeyException] will
 * be raised
 * - it exposes [onIvNotSecureToUse] callback for subclasses where a wrong IV length will throw a
 * [AesInvalidIvException] and an iv with zeroes only will have this method return false.
 * Subclasses would implement the desired behaviour
 */
internal abstract class AesSanityChecks(protected val mode: AesBlockMode) {

    init {
        //Temporary until implemented, although not ideal
        if (mode == CTR || mode == GCM) {
            throw AesNotImplementedException("CTR and GCM block mode are not implemented yet")
        }
    }

    /**
     * Validates if the key is properly initialised.
     * Check the the key length is matching one of 3 keys size supported. And if the key
     * is initialised with all zeroes only.
     * @throws AesInvalidKeyException is the key length is unknown: not (128, 192, or 256 bits). Or
     * when the key is initialised with only zeroes.
     */
    fun validateAesKey(key: AesKey) {
        AesKeysLength.values().firstOrNull { it.lengthBytes == key.material.size }
                ?: throw AesInvalidKeyException(
                        "The key length, in bits, must match one " +
                                "of: ${AesKeysLength.values().joinToString { entry -> entry.lengthBits.toString() }}" +
                                ", found ${key.material.size * 8}"
                )

        if (key.all { it == 0.toByte() }) {
            throw AesInvalidKeyException(
                    "The key should not be only zeroes. It should be randomized.\n" +
                            "Try to use methods that generates random keys for you or the AesSecureRandom"
            )
        }
    }

    /**
     * Validates if the IV is properly initialised.
     * Calls [isIvSecureToUse] and delegates the case where it returns `false` to subclasses.
     * If this methods returns true then nothing happen and the IV is consider safe to use.
     */
    fun validateIv(iv: IV) {
        if (isIvSecureToUse(iv).not()) {
            onIvNotSecureToUse()
        }
    }

    /**
     * Check if the IV length matches the block size and if it is not all zeroes.
     * @return true if the IV does not contain only zeroes, false otherwise
     * @throws AesInvalidIvException if the iv does not match the block size
     */
    private fun isIvSecureToUse(iv: IV): Boolean {
        if (iv.size != mode.ivLengthBytes) {
            throw AesInvalidIvException("The IV should be ${mode.ivLengthBytes} long, it is: ${iv.size}")
        }

        // Not secure to have an IV set to null
        return iv.all { it == 0.toByte() }.not()
    }

    /**
     * Invoked when the IV has been deemed not secure to use.
     * @see [isIvSecureToUse] for more info
     *
     */
    internal abstract fun onIvNotSecureToUse()
}
