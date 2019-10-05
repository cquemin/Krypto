package com.island.yoshiz.mpp.krypto.aes.ciphers

import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CBC
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CTR
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.GCM
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes128
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes192
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes256
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
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import kotlinx.cinterop.refTo
import kotlinx.cinterop.toCValues
import kotlinx.cinterop.value
import platform.CoreCrypto.CCCryptorCreateWithMode
import platform.CoreCrypto.CCCryptorFinal
import platform.CoreCrypto.CCCryptorGetOutputLength
import platform.CoreCrypto.CCCryptorRefVar
import platform.CoreCrypto.CCCryptorRelease
import platform.CoreCrypto.CCCryptorUpdate
import platform.CoreCrypto.ccNoPadding
import platform.CoreCrypto.kCCAlgorithmAES
import platform.CoreCrypto.kCCBlockSizeAES128
import platform.CoreCrypto.kCCDecrypt
import platform.CoreCrypto.kCCEncrypt
import platform.CoreCrypto.kCCKeySizeAES128
import platform.CoreCrypto.kCCKeySizeAES192
import platform.CoreCrypto.kCCKeySizeAES256
import platform.CoreCrypto.kCCModeCBC
import platform.CoreCrypto.kCCModeCTR
import platform.CoreCrypto.kCCOptionPKCS7Padding
import platform.CoreCrypto.kCCSuccess
import platform.darwin.nil
import platform.posix.memcpy
import platform.posix.size_t
import platform.posix.size_tVar

@ExperimentalUnsignedTypes
internal actual class AesNativeCipher actual constructor(
        private val keyLength: AesKeysLength,
        private val mode: AesBlockMode,
        private val padding: Padding?
) : NativeCipher {

    private lateinit var cryptor: CCCryptorRefVar
    private lateinit var cryptOperation: Operation
    private var expectedLength: size_t = 0.convert()
    private var _isInitiliased = false

    /**
     * Initialise internal structures with the key and iv submitted
     * This method must be called first
     */
    override fun init(
            iv: ByteArray, aesKey: ByteArray,
            operation: Operation
    ) {

        cryptOperation = operation
        cryptor = nativeHeap.alloc()

        // Initialise with the required mode
        val cryptStatus = CCCryptorCreateWithMode(
                getCipherMode(operation),
                modeConstant,
                kCCAlgorithmAES,
                paddingConstant,
                iv.toCValues(),
                aesKey.toCValues(),
                keyLengthConstant.convert(),
                nil,
                0,
                0,
                0,
                cryptor.ptr
        )

        if (cryptStatus != kCCSuccess) {
            throw getAesException(operation, "Unable to create the crypto cipher : $cryptStatus")
        } else {
            _isInitiliased = true
        }
    }

    /**
     * Update the current cipher with the next bunch of data.
     * If the data length is less than the block size then the returned buffer will be empty
     */
    override fun update(data: ByteArray, offset: Int, size: Int): ByteArray = memScoped {
        checkInit()

        expectedLength = CCCryptorGetOutputLength(
                cryptor.value,
                data.size.convert(),
                true // include the required size for the update and for the finalise call
        )

        val buffer = allocArray<ByteVar>(expectedLength.convert())
        val writtenUpdate = alloc<size_tVar>()

        // Update with the current input.
        val cryptStatus = CCCryptorUpdate(
                cryptor.value,
                data.copyOfRange(offset, offset + size).toCValues(),
                size.convert(),
                buffer,
                expectedLength.convert(),
                writtenUpdate.ptr
        )

        if (cryptStatus == kCCSuccess) {
            val written = writtenUpdate.value
            val result = ByteArray(written.convert())

            // Only copy if there is something to copy otherwise memcpy will crash with kotlin.ArrayIndexOutOfBoundsException
            if (written > 0.convert()) {
                memcpy(result.refTo(0), buffer, written)
            }

            // update the remaining length for the allocation for the finalise call
            expectedLength -= written

            return@memScoped result
        }

        throw getAesException(
                cryptOperation, "Unable to update the current buffer: $cryptStatus, " +
                "data read: ${writtenUpdate.value}"
        )
    }

    /**
     * Finalise a multipart operation. return the data left not returned by [update]
     */
    override fun finalise(): ByteArray = memScoped {
        checkInit()

        val buffer = allocArray<ByteVar>(expectedLength.convert())
        val writtenFinal = alloc<size_tVar>()

        // Finalising to get the rest of the data
        val cryptStatus = CCCryptorFinal(
                cryptor.value,
                buffer,
                expectedLength,
                writtenFinal.ptr
        )

        CCCryptorRelease(cryptor.value)
        nativeHeap.free(cryptor.rawPtr)

        if (cryptStatus == kCCSuccess) {
            val writtenTotal = writtenFinal.value
            val result = ByteArray(writtenTotal.convert())
            memcpy(result.refTo(0), buffer, writtenTotal)

            _isInitiliased = false
            return@memScoped result
        }

        throw getAesException(cryptOperation, "Unable to finalise the crypto cipher : $cryptStatus")
    }

    override fun getOutputSize(inputLength: Int): Int {
        val size = CCCryptorGetOutputLength(
                cryptor.value,
                inputLength.convert(),
                true
        )

        return size.convert()
    }

    private fun checkInit() {
        if (_isInitiliased.not()) {
            throw CipherException("The cipher has not been initialised. Call init")
        }
    }

    private fun getAesException(operation: Operation, msg: String): AesException {
        val conf = "AES/$mode/$padding/$keyLength"
        return if (operation == ENCRYPT) {
            AesEncryptionException("Encrypt[$conf] - $msg")
        } else {
            AesDecryptionException("Decrypt[$conf] - $msg")
        }
    }

    private val keyLengthConstant: UInt
        get() {
            return when (keyLength) {
                Aes128 -> kCCKeySizeAES128
                Aes192 -> kCCKeySizeAES192
                Aes256 -> kCCKeySizeAES256
            }
        }

    private val paddingConstant: UInt
        get() {
            return when (padding) {
                PKCS5 -> kCCOptionPKCS7Padding
                PKCS7 -> kCCOptionPKCS7Padding
                null -> ccNoPadding
            }
        }

    private val modeConstant: UInt
        get() {
            return when (mode) {
                CBC -> kCCModeCBC
                CTR -> kCCModeCTR
                GCM -> TODO()
            }
        }

    private fun getCipherMode(operation: Operation): UInt {
        return when (operation) {
            DECRYPT -> kCCDecrypt
            ENCRYPT -> kCCEncrypt
        }
    }

    private fun getPaddingLength(operation: Operation): UInt {
        return when (operation) {
            DECRYPT -> 0.toUInt()
            ENCRYPT -> kCCBlockSizeAES128
        }
    }
}