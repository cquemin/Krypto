package com.island.yoshiz.mpp.krypto.aes.engines

import com.island.yoshiz.mpp.krypto.ENCRYPTION_KEY_B64
import com.island.yoshiz.mpp.krypto.IV_B64
import com.island.yoshiz.mpp.krypto.aes.checks.AesInputSanityCheck
import com.island.yoshiz.mpp.krypto.aes.ciphers.AesFileCipher
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CBC
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes256
import com.island.yoshiz.mpp.krypto.aes.model.config.Padding.PKCS7
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesInvalidIvException
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesInvalidKeyException
import com.island.yoshiz.mpp.krypto.aes.model.file.AesEncryptedFileAndIV
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKey
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKeyIv
import com.island.yoshiz.mpp.krypto.aes.model.keys.IV
import com.island.yoshiz.mpp.krypto.aes.random.AesSecureRandom
import com.island.yoshiz.mpp.krypto.common.utils.Base64Factory
import io.mockk.*
import io.mockk.impl.annotations.MockK
import kotlin.test.*

@ExperimentalStdlibApi
internal class AesFileEngineTest {

    private lateinit var engine: AesFileEngine

    @MockK
    private lateinit var inputChecksMock: AesInputSanityCheck

    @MockK
    private lateinit var randomGeneratorMock: AesSecureRandom

    @MockK
    private lateinit var aesFileCipherMock: AesFileCipher

    private val base64Engine = Base64Factory.createEngine()
    private val aesKey = AesKey(base64Engine.decode(ENCRYPTION_KEY_B64))
    private val iv = IV(base64Engine.decode(IV_B64))
    private val aesKeyIv = AesKeyIv(iv, aesKey)

    private val decryptedFlePath = "decrypted_file"
    private val encryptedFlePath = "encrypted_file"

    private val encryptedFile = AesEncryptedFileAndIV(aesKeyIv, encryptedFlePath)

    @BeforeTest
    fun setUp() {
        MockKAnnotations.init(this)

        engine = AesFileEngine(
                Aes256,
                CBC,
                PKCS7,
                inputChecksMock,
                randomGeneratorMock,
                aesFileCipherMock
        )

        every { randomGeneratorMock.generateAesKey() } returns aesKey
        every { randomGeneratorMock.generateIv() } returns iv
        every { randomGeneratorMock.generateAesKeyAndIv() } returns aesKeyIv

        every { inputChecksMock.validateAesKey(aesKey) } returns Unit
        every { inputChecksMock.validateIv(iv) } returns Unit

        every {
            aesFileCipherMock.encrypt(
                    eq(decryptedFlePath),
                    eq(iv.data),
                    eq(aesKey.material),
                    any(),
                    any()
            )
        } returns encryptedFlePath

        every {
            aesFileCipherMock.decrypt(
                    eq(encryptedFlePath),
                    eq(iv.data),
                    eq(aesKey.material),
                    any(),
                    any()
            )
        } returns decryptedFlePath
    }

    @Test
    fun givenEncryptFile_andNoKeyOrIv_andReplace_thenKeyIvEncryptedDataGenerated() {

        val result = engine.encrypt(decryptedFlePath, true)

        assertEquals(aesKeyIv, result.keyIv)
        assertEquals(encryptedFlePath, result.pathToFile)

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify {
            aesFileCipherMock.encrypt(
                    decryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = true, expectIvInFile = false
            )
        }

        verify { randomGeneratorMock.generateAesKeyAndIv() }
    }

    @Test
    fun givenEncryptFile_andCheckInvalidIv_andReplace_thenThrowAesInvalidIvException() {
        every { inputChecksMock.validateIv(iv) } throws AesInvalidIvException("invalid IV")

        assertFailsWith(AesInvalidIvException::class) {
            engine.encrypt(decryptedFlePath, true)
        }

        verify { inputChecksMock.validateIv(iv) }

        verify(exactly = 0) { inputChecksMock.validateAesKey(aesKey) }
        verify(exactly = 0) {
            aesFileCipherMock.encrypt(
                    decryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = true, expectIvInFile = false
            )
        }

        verify { randomGeneratorMock.generateAesKeyAndIv() }
    }

    @Test
    fun givenEncryptFile_andCheckInvalidAesKey_andReplace_thenThrowAesInvalidKeyException() {
        every { inputChecksMock.validateAesKey(aesKey) } throws AesInvalidKeyException("invalid AesKey")

        assertFailsWith(AesInvalidKeyException::class) {
            engine.encrypt(decryptedFlePath, true)
        }

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify(exactly = 0) {
            aesFileCipherMock.encrypt(
                    decryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = true, expectIvInFile = false
            )
        }

        verify { randomGeneratorMock.generateAesKeyAndIv() }
    }

    @Test
    fun givenEncryptFile_andKeySubmitted_andReplace_thenIvEncryptedDataGenerated() {

        val result = engine.encrypt(aesKey, decryptedFlePath, true)

        assertEquals(aesKeyIv, result.keyIv)
        assertEquals(encryptedFlePath, result.pathToFile)

        verify { randomGeneratorMock.generateIv() }
        verify(exactly = 0) { randomGeneratorMock.generateAesKey() }

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify {
            aesFileCipherMock.encrypt(
                    decryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = true, expectIvInFile = false
            )
        }
    }

    @Test
    fun givenEncryptFile_andInvalidIv_andReplace_thenThrowAesInvalidIvException() {
        every { inputChecksMock.validateIv(iv) } throws AesInvalidIvException("invalid IV")

        assertFailsWith(AesInvalidIvException::class) {
            engine.encrypt(aesKey, decryptedFlePath, true)
        }

        verify { randomGeneratorMock.generateIv() }
        verify { inputChecksMock.validateIv(iv) }
        verify(exactly = 0) { randomGeneratorMock.generateAesKey() }

        verify(exactly = 0) { inputChecksMock.validateAesKey(aesKey) }
        verify(exactly = 0) {
            aesFileCipherMock.encrypt(
                    decryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = true, expectIvInFile = false
            )
        }
    }

    @Test
    fun givenEncryptFile_andKeyIvSubmitted_andReplace_thenKeyIvEncryptedDataGenerated() {
        val result = engine.encrypt(aesKeyIv, decryptedFlePath, true)

        assertEquals(aesKeyIv, result.keyIv)
        assertEquals(encryptedFlePath, result.pathToFile)

        verify(exactly = 0) { randomGeneratorMock.generateIv() }
        verify(exactly = 0) { randomGeneratorMock.generateAesKey() }

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify {
            aesFileCipherMock.encrypt(
                    decryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = true, expectIvInFile = false
            )
        }
    }

    @Test
    fun givenDecryptFile_andCorrectParams_andReplace_thenReturnDecryptedData() {
        val result = engine.decrypt(encryptedFile, true)

        assertEquals(aesKeyIv, result.keyIv)
        assertEquals(decryptedFlePath, result.pathToFile)

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify {
            aesFileCipherMock.decrypt(
                    encryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = true, expectIvInFile = false
            )
        }
    }

    @Test
    fun givenDecryptFile_andInvalidIv_andReplace_thenThrowAesInvalidIvException() {
        every { inputChecksMock.validateIv(iv) } throws AesInvalidIvException("invalid IV")

        assertFailsWith(AesInvalidIvException::class) {
            engine.decrypt(encryptedFile, true)
        }

        verify { inputChecksMock.validateIv(iv) }

        verify(exactly = 0) { inputChecksMock.validateAesKey(aesKey) }
        verify(exactly = 0) {
            aesFileCipherMock.decrypt(
                    encryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = true, expectIvInFile = false
            )
        }
    }

    @Test
    fun givenDecryptFile_andInvalidAesKey_andReplace_thenThrowAesInvalidKeyException() {
        every { inputChecksMock.validateAesKey(aesKey) } throws AesInvalidKeyException("invalid key")

        assertFailsWith(AesInvalidKeyException::class) {
            engine.decrypt(encryptedFile, true)
        }

        verify(exactly = 0) {
            aesFileCipherMock.decrypt(
                    encryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = true, expectIvInFile = false
            )
        }

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }
    }

    @Test
    fun givenDecryptFile_andCorrectParams_andNotReplace_thenReturnDecryptedData() {
        val result = engine.decrypt(encryptedFile, false)

        assertEquals(aesKeyIv, result.keyIv)
        assertEquals(decryptedFlePath, result.pathToFile)

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify {
            aesFileCipherMock.decrypt(
                    encryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = false, expectIvInFile = false
            )
        }
    }

    @Test
    fun givenDecryptFile_andCorrectParams_andNotReplace_andPersistIv_thenReturnDecryptedData() {
        val result = engine.decryptWithIvFromFile(encryptedFile, false)

        assertEquals(aesKeyIv, result.keyIv)
        assertEquals(decryptedFlePath, result.pathToFile)

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify {
            aesFileCipherMock.decrypt(
                    encryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = false, expectIvInFile = true
            )
        }
    }

    @Test
    fun givenDecryptFile_andCorrectParams_andReplace_andPersistIv_thenReturnDecryptedData() {
        val result = engine.decryptWithIvFromFile(encryptedFile, true)

        assertEquals(aesKeyIv, result.keyIv)
        assertEquals(decryptedFlePath, result.pathToFile)

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify {
            aesFileCipherMock.decrypt(
                    encryptedFlePath, iv.data, aesKey.material,
                    replaceOriginal = true, expectIvInFile = true
            )
        }
    }
}