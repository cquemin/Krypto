package com.island.yoshiz.mpp.krypto.aes.ciphers

import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CBC
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CTR
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.GCM
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength
import com.island.yoshiz.mpp.krypto.aes.model.config.Padding
import com.island.yoshiz.mpp.krypto.aes.model.config.Padding.PKCS5
import com.island.yoshiz.mpp.krypto.aes.model.config.Padding.PKCS7
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesDecryptionException
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesEncryptionException
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesException
import com.island.yoshiz.mpp.krypto.common.NativeCipher
import com.island.yoshiz.mpp.krypto.common.Operation
import com.island.yoshiz.mpp.krypto.common.Operation.DECRYPT
import com.island.yoshiz.mpp.krypto.common.Operation.ENCRYPT
import com.island.yoshiz.mpp.krypto.common.model.exceptions.CipherException
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal actual class AesNativeCipher actual constructor(
        private val keyLength: AesKeysLength,
        private val mode: AesBlockMode,
        private val padding: Padding?
) : NativeCipher {

    private lateinit var cipher: Cipher
    private lateinit var operation: Operation
    private var _isInitiliased = false

    /**
     * Initialise internal structures with the key and iv submitted
     * This method must be called first
     */
    override fun init(
            iv: ByteArray,
            aesKey: ByteArray,
            operation: Operation
    ) {
        this.operation = operation
        cipher = generateAESCBCCipherAr(iv, aesKey)
        _isInitiliased = true
    }

    /**
     * Update the current cipher with the next bunch of data.
     * If the data length is less than the block size then the returned buffer will be empty
     */
    override fun update(data: ByteArray, offset: Int, size: Int): ByteArray {
        checkInit()

        try {
            return cipher.update(data, offset, size)
        } catch (exception: GeneralSecurityException) {
            throw getAesException("Unable to update the cipher", exception)
        }
    }

    /**
     * Finalise a multipart operation. return the data left not returned by [update]
     */
    override fun finalise(): ByteArray {
        checkInit()

        try {
            val finalised: ByteArray? = cipher.doFinal()
            _isInitiliased = false
            return finalised ?: ByteArray(0)
        } catch (exception: GeneralSecurityException) {
            throw getAesException("Unable to finalise", exception)
        }
    }

    override fun getOutputSize(inputLength: Int): Int {
        checkInit()

        return cipher.getOutputSize(inputLength)
    }

    private fun checkInit() {
        if (_isInitiliased.not()) {
            throw CipherException("The cipher has not been initialised. Call init")
        }
    }

    private fun generateAESCBCCipherAr(iv: ByteArray, key: ByteArray): Cipher {
        try {
            val mode = getCipherMode(operation)
            val cipher = Cipher.getInstance(aesTransformation)
            val ivSpec = IvParameterSpec(iv)
            val secretKeySpec = SecretKeySpec(key, "AES")
            cipher.init(mode, secretKeySpec, ivSpec)

            return cipher
        } catch (exception: GeneralSecurityException) {
            throw getAesException("Unable to create the native cipher", exception)
        }
    }

    private fun getAesException(msg: String, cause: Throwable): AesException {
        val conf = "AES/$mode/$padding/$keyLength"
        return if (operation == ENCRYPT) {
            AesEncryptionException("Encrypt[$conf] - $msg", cause)
        } else {
            AesDecryptionException("Decrypt[$conf] - $msg", cause)
        }
    }

    private val aesTransformation: String = "AES/$modeTransformation/$paddingTransformation"

    private val modeTransformation: String
        get() {
            return when (mode) {
                CBC -> "CBC"
                CTR -> "CTR"
                GCM -> "GCM"
            }
        }

    private val paddingTransformation: String
        get() {
            return when (padding) {
                PKCS5 -> "PKCS5Padding"
                PKCS7 -> "PKCS5Padding" // Java uses PKCS5 constant even though it is technically PKCS7
                null -> "NoPadding"
            }
        }

    private fun getCipherMode(operation: Operation): Int {
        return when (operation) {
            DECRYPT -> Cipher.DECRYPT_MODE
            ENCRYPT -> Cipher.ENCRYPT_MODE
        }
    }
}