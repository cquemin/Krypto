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
import com.island.yoshiz.mpp.krypto.common.model.files.File
import com.island.yoshiz.mpp.krypto.common.model.streams.FileInputStream
import com.island.yoshiz.mpp.krypto.common.model.streams.FileOutputStream
import com.island.yoshiz.mpp.krypto.common.utils.Base64Factory
import kotlin.test.*

@ExperimentalStdlibApi
internal class AesFileCipherTest {

    private val testFileClear = File("aes_encryption_test.decrypted.txt")
    private val testFileEncrypted = File("aes_encryption_test.encrypted.txt")

    private val aesConf = AES_CBC_PKCS7_256
    private val base64Engine = Base64Factory.createEngine()
    private val aesKeyIv = AesKeyIv(
            base64Engine.decode(IV_B64),
            base64Engine.decode(ENCRYPTION_KEY_B64)
    )

    private lateinit var fileCipher: AesFileCipher
    private lateinit var tempFilePath: String

    @BeforeTest
    fun setup() {
        fileCipher = AesFileCipher(aesConf.keyLength, aesConf.mode, aesConf.padding)
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andShortLongText_thenEncryptionSuccess() {
        testEncrypt(MESSAGE_BELOW_BLOCK_SIZE, MESSAGE_BELOW_BLOCK_SIZE_ENCRYPTED_B64,
                replaceFile = false,
                persistIv = false
        )
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andLongText_thenEncryptionSuccess() {
        testEncrypt(MESSAGE_LONG, MESSAGE_LONG_ENCRYPTED_B64,
                replaceFile = false,
                persistIv = false
        )
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andReallyLongText_thenEncryptionSuccess() {
        testEncrypt(MESSAGE_REALLY_LONG, MESSAGE_REALLY_LONG_ENCRYPTED_B64,
                replaceFile = false,
                persistIv = false
        )
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andShortLongText_andReplaceOriginal_thenEncryptionSuccess() {
        testEncrypt(MESSAGE_BELOW_BLOCK_SIZE, MESSAGE_BELOW_BLOCK_SIZE_ENCRYPTED_B64,
                replaceFile = true,
                persistIv = false
        )
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andLongText_andReplaceOriginal_thenEncryptionSuccess() {
        testEncrypt(MESSAGE_LONG, MESSAGE_LONG_ENCRYPTED_B64,
                replaceFile = true,
                persistIv = false
        )
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andReallyLongText_andReplaceOriginal_thenEncryptionSuccess() {
        testEncrypt(MESSAGE_REALLY_LONG, MESSAGE_REALLY_LONG_ENCRYPTED_B64,
                replaceFile = true,
                persistIv = false
        )
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andShortLongText_andPersistIv_thenEncryptionSuccess() {
        testEncrypt(MESSAGE_BELOW_BLOCK_SIZE, MESSAGE_BELOW_BLOCK_SIZE_ENCRYPTED_B64,
                replaceFile = false,
                persistIv = true
        )
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andLongText_andPersistIv_thenEncryptionSuccess() {
        testEncrypt(MESSAGE_LONG, MESSAGE_LONG_ENCRYPTED_B64,
                replaceFile = false,
                persistIv = true
        )
    }

    @Test
    fun testEncrypt_givenAES_CBC_PKCS7_256_andReallyLongText_andPersistIv_thenEncryptionSuccess() {
        testEncrypt(MESSAGE_REALLY_LONG, MESSAGE_REALLY_LONG_ENCRYPTED_B64,
                replaceFile = false,
                persistIv = true
        )
    }

    private fun testEncrypt(
            messageClear: String, messageEncrypted: String,
            replaceFile: Boolean, persistIv: Boolean
    ) {
        prepareClearFile(messageClear.encodeToByteArray())

        tempFilePath = fileCipher.encrypt(
                testFileClear.getAbsolutePath(),
                aesKeyIv.iv.data,
                aesKeyIv.aesKey.material,
                replaceFile,
                persistIv
        )

        // check that the return files contains the encrypted content
        val buffer = ByteArray(1024)
        val encryptedStream = FileInputStream(File(tempFilePath))
        val sizeRead = encryptedStream.read(buffer)
        val result = buffer.copyOf(sizeRead)

        assertTrue {
            base64Engine
                    .decode(messageEncrypted)
                    .contentEquals(result)
        }
    }

    @Test
    fun testDecrypt_givenAES_CBC_PKCS7_256_andShortText_thenDecryptSuccess() {
        testDecrypt(MESSAGE_BELOW_BLOCK_SIZE, MESSAGE_BELOW_BLOCK_SIZE_ENCRYPTED_B64,
                replaceFile = false,
                persistedIv = false
        )
    }

    @Test
    fun testDecrypt_givenAES_CBC_PKCS7_256_andLongText_thenDecryptSuccess() {
        testDecrypt(MESSAGE_LONG, MESSAGE_LONG_ENCRYPTED_B64,
                replaceFile = false,
                persistedIv = false
        )
    }

    @Test
    fun testDecrypt_givenAES_CBC_PKCS7_256_andReallyLongText_thenDecryptSuccess() {
        testDecrypt(MESSAGE_REALLY_LONG, MESSAGE_REALLY_LONG_ENCRYPTED_B64,
                replaceFile = false,
                persistedIv = false
        )
    }

    private fun testDecrypt(
            clearMessage: String, encryptedMessage: String,
            replaceFile: Boolean, persistedIv: Boolean
    ) {
        prepareEncryptedFile(base64Engine.decode(encryptedMessage))

        tempFilePath = fileCipher.decrypt(
                testFileEncrypted.getAbsolutePath(),
                aesKeyIv.iv.data,
                aesKeyIv.aesKey.material,
                replaceFile,
                persistedIv
        )

        // check that the return files contains the decrypted content
        val buffer = ByteArray(1024)
        val decryptedStream = FileInputStream(File(tempFilePath))
        val sizeRead = decryptedStream.read(buffer)
        val result = buffer.copyOf(sizeRead)

        assertTrue {
            clearMessage.encodeToByteArray().contentEquals(result)
        }
    }

    private fun prepareClearFile(messageClear: ByteArray) {
        val testFileStream = FileOutputStream(testFileClear)
        testFileStream.write(messageClear, 0, messageClear.size)
        testFileStream.flush()
        testFileStream.close()
    }

    private fun prepareEncryptedFile(messageEncrypted: ByteArray) {
        val testFileEncrypted = FileOutputStream(testFileEncrypted)
        testFileEncrypted.write(messageEncrypted, 0, messageEncrypted.size)
        testFileEncrypted.flush()
        testFileEncrypted.close()
    }

    @AfterTest
    fun cleanup() {
        testFileClear.delete()
        testFileEncrypted.delete()
        File(tempFilePath).delete()
    }
}