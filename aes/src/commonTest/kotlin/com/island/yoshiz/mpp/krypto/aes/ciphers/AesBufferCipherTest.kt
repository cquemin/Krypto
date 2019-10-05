package com.island.yoshiz.mpp.krypto.aes.ciphers

import com.island.yoshiz.mpp.krypto.ENCRYPTION_KEY_B64
import com.island.yoshiz.mpp.krypto.IV_B64
import com.island.yoshiz.mpp.krypto.MESSAGE_BELOW_BLOCK_SIZE
import com.island.yoshiz.mpp.krypto.MESSAGE_BELOW_BLOCK_SIZE_ENCRYPTED_B64
import com.island.yoshiz.mpp.krypto.MESSAGE_LONG
import com.island.yoshiz.mpp.krypto.MESSAGE_LONG_ENCRYPTED_B64
import com.island.yoshiz.mpp.krypto.MESSAGE_REALLY_LONG
import com.island.yoshiz.mpp.krypto.MESSAGE_REALLY_LONG_ENCRYPTED_B64
import com.island.yoshiz.mpp.krypto.aes.model.config.AesConfiguration.AES_CBC_PKCS7_256
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKeyIv
import com.island.yoshiz.mpp.krypto.common.utils.Base64Factory
import com.island.yoshiz.mpp.krypto.common.utils.extensions.byteToCharArray
import kotlin.test.*

@ExperimentalStdlibApi
class AesBufferCipherTest {

    private val aesConf = AES_CBC_PKCS7_256
    private val base64Engine = Base64Factory.createEngine()
    private val keyIv = AesKeyIv(
            base64Engine.decode(IV_B64),
            base64Engine.decode(ENCRYPTION_KEY_B64)
    )

    private lateinit var bufferCipher: AesBufferCipher

    @BeforeTest
    fun setup() {
        bufferCipher = AesBufferCipher(aesConf.keyLength, aesConf.mode, aesConf.padding)
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andShortText_thenEncryptionSuccess() {
        performEncryptionAndAssert(MESSAGE_BELOW_BLOCK_SIZE, MESSAGE_BELOW_BLOCK_SIZE_ENCRYPTED_B64)
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andLongText_thenEncryptionSuccess() {
        performEncryptionAndAssert(MESSAGE_LONG, MESSAGE_LONG_ENCRYPTED_B64)
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andReallyLongText_thenEncryptionSuccess() {
        performEncryptionAndAssert(MESSAGE_REALLY_LONG, MESSAGE_REALLY_LONG_ENCRYPTED_B64)
    }

    private fun performEncryptionAndAssert(clearText: String, encryptedTextB64: String) {
        val encrypted = bufferCipher.encrypt(
                clearText.encodeToByteArray(),
                keyIv.iv.data,
                keyIv.aesKey.material
        )

        val encryptedBase64 = base64Engine.encode(encrypted).byteToCharArray()

        assertEquals(encryptedTextB64, String(encryptedBase64))
    }

    @Test
    fun testDecrypt_givenAES_CBC_PKCS7_256_andShortEncryptedText_thenDecryptionSuccess() {
        performDecryptionAndAssert(MESSAGE_BELOW_BLOCK_SIZE_ENCRYPTED_B64, MESSAGE_BELOW_BLOCK_SIZE)
    }

    @Test
    fun testDecrypt_givenAES_CBC_PKCS7_256_andLongEncryptedText_thenDecryptionSuccess() {
        performDecryptionAndAssert(MESSAGE_LONG_ENCRYPTED_B64, MESSAGE_LONG)
    }

    @Test
    fun testDecrypt_givenAES_CBC_PKCS7_256_andReallyLongEncryptedText_thenDecryptionSuccess() {
        performDecryptionAndAssert(MESSAGE_REALLY_LONG_ENCRYPTED_B64, MESSAGE_REALLY_LONG)
    }

    private fun performDecryptionAndAssert(encryptedTextB64: String, clearText: String) {
        val encrypted = base64Engine.decode(encryptedTextB64)

        val decrypted = bufferCipher.decrypt(encrypted, keyIv.iv.data, keyIv.aesKey.material)

        assertEquals(clearText, String(decrypted.byteToCharArray()))
    }
}