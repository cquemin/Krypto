package com.island.yoshiz.mpp.krypto.aes.ciphers

import com.island.yoshiz.mpp.krypto.aes.model.buffer.AesEncryptedData
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength
import com.island.yoshiz.mpp.krypto.aes.model.config.Padding
import com.island.yoshiz.mpp.krypto.common.Operation
import com.island.yoshiz.mpp.krypto.common.Operation.DECRYPT
import com.island.yoshiz.mpp.krypto.common.Operation.ENCRYPT

/**
 * Implements the actual operation of encryption and decryption for AES transformation on a buffer.
 * The underlying AES transformation is delegated to an [AesNativeCipher] instance
 */
internal class AesBufferCipher constructor(
        keyLength: AesKeysLength,
        mode: AesBlockMode,
        padding: Padding?
) {

    private var cipher = AesNativeCipher(keyLength, mode, padding)

    /**
     * Performs the AES decryption according to parameters passed at construction time
     * This consider that the content of [dataToDecrypt] is valid. Checks must be performed before
     * this method is called.
     */
    fun decrypt(
            dataToDecrypt: ByteArray,
            iv: ByteArray,
            aesKey: ByteArray
    ): ByteArray {
        return performBufferOperation(dataToDecrypt, iv, aesKey, DECRYPT)
    }

    /**
     * Performs the AES encryption according to parameters passed at construction time
     * This will return a valid instance of [AesEncryptedData]
     */
    fun encrypt(
            dataToEncrypt: ByteArray,
            iv: ByteArray,
            aesKey: ByteArray
    ): ByteArray {
        return performBufferOperation(dataToEncrypt, iv, aesKey, ENCRYPT)
    }

    private fun performBufferOperation(
            data: ByteArray,
            iv: ByteArray,
            aesKey: ByteArray,
            operation: Operation
    ): ByteArray {
        cipher.init(iv, aesKey, operation)
        val update = cipher.update(data, 0, data.size)
        val finalised = cipher.finalise()
        return update + finalised
    }
}