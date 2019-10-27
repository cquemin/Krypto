package com.island.yoshiz.mpp.krypto.aes.engines

import com.island.yoshiz.mpp.krypto.aes.checks.AesSanityChecks
import com.island.yoshiz.mpp.krypto.aes.ciphers.AesBufferCipher
import com.island.yoshiz.mpp.krypto.aes.model.buffer.AesDecryptedData
import com.island.yoshiz.mpp.krypto.aes.model.buffer.AesEncryptedData
import com.island.yoshiz.mpp.krypto.aes.model.buffer.PlainData
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength
import com.island.yoshiz.mpp.krypto.aes.model.config.Padding
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKey
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKeyIv
import com.island.yoshiz.mpp.krypto.aes.model.keys.IV
import com.island.yoshiz.mpp.krypto.aes.random.AesSecureRandom

/**
 * Offers several way to encrypt data. The recommended way would be to let this class generate the IV
 * for you which will be returned as a result of the encrypted data. Offers as well ways to decrypt
 */
class AesBufferEngine internal constructor(
        keyLength: AesKeysLength,
        mode: AesBlockMode,
        padding: Padding?,
        private val inputChecks: AesSanityChecks,
        private val secureGenerator: AesSecureRandom = AesSecureRandom(keyLength, mode),
        private val bufferCipher: AesBufferCipher = AesBufferCipher(keyLength, mode, padding)
) {


    /**
     * Encrypt the data with AES. Will securely generate an AES key of the right length and an IV of
     * the correct length
     *
     * @param plainData     the data to encrypt
     * @return the encrypted data
     */
    fun encrypt(plainData: PlainData): AesEncryptedData {
        val keyIv = secureGenerator.generateAesKeyAndIv()
        return encrypt(keyIv, plainData)
    }

    /**
     * Encrypt the data with AES from the key submitted. It will securely generate an IV of the
     * right length
     *
     * @param key           the key for the encryption
     * @param plainData     the data to encrypt
     * @return the encrypted data
     */
    fun encrypt(key: AesKey, plainData: PlainData): AesEncryptedData {
        val iv = secureGenerator.generateIv()
        return encrypt(AesKeyIv(iv, key), plainData)
    }

    /**
     * This method is discouraged to use. It is kept for legacy purpose where you might need to
     * decrypt the data manually and the use the method where either the IV [encrypt] or both the
     * key and IV [encrypt] are generated for you.
     */
    fun encrypt(keyIv: AesKeyIv, plainData: PlainData): AesEncryptedData {
        validateInputs(keyIv.aesKey, keyIv.iv)

        val encryptedData = bufferCipher.encrypt(plainData, keyIv.iv.data, keyIv.aesKey.material)
        return AesEncryptedData(keyIv.iv, keyIv.aesKey, encryptedData)
    }

    /**
     * Decrypt the data with the submitted key and iv
     *
     * @param dataToDecrypt the encrypted data to decrypt and the IV
     * @return decrypted data
     */
    fun decrypt(dataToDecrypt: AesEncryptedData): AesDecryptedData {
        return decrypt(dataToDecrypt.encryptedData, dataToDecrypt.aesKey, dataToDecrypt.iv)
    }

    /**
     * Decrypt the data with the submitted key and iv
     *
     * @param dataToDecrypt the encrypted data to decrypt and the IV
     * @return decrypted data
     */
    fun decrypt(dataToDecrypt: ByteArray, aesKey: AesKey, iv: IV): AesDecryptedData {
        validateInputs(aesKey, iv)

        return bufferCipher.decrypt(dataToDecrypt, iv.data, aesKey.material)
    }

    private fun validateInputs(aesKey: AesKey, iv: IV) {
        inputChecks.validateIv(iv)
        inputChecks.validateAesKey(aesKey)
    }
}

