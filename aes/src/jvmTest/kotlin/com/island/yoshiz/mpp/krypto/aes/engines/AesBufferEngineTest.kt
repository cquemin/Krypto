package com.island.yoshiz.mpp.krypto.aes.engines

import com.island.yoshiz.mpp.krypto.ENCRYPTION_KEY_B64
import com.island.yoshiz.mpp.krypto.IV_B64
import com.island.yoshiz.mpp.krypto.MESSAGE_LONG
import com.island.yoshiz.mpp.krypto.MESSAGE_LONG_ENCRYPTED_B64
import com.island.yoshiz.mpp.krypto.aes.checks.AesInputSanityCheck
import com.island.yoshiz.mpp.krypto.aes.ciphers.AesBufferCipher
import com.island.yoshiz.mpp.krypto.aes.model.buffer.AesEncryptedData
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CBC
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes256
import com.island.yoshiz.mpp.krypto.aes.model.config.Padding.PKCS7
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesInvalidIvException
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesInvalidKeyException
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKey
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKeyIv
import com.island.yoshiz.mpp.krypto.aes.model.keys.IV
import com.island.yoshiz.mpp.krypto.aes.random.AesSecureRandom
import com.island.yoshiz.mpp.krypto.common.utils.Base64Factory
import io.mockk.*
import io.mockk.impl.annotations.MockK
import kotlin.test.*

@ExperimentalStdlibApi
internal class AesBufferEngineTest {

    private lateinit var engine: AesBufferEngine

    @MockK
    private lateinit var inputChecksMock: AesInputSanityCheck

    @MockK
    private lateinit var randomGeneratorMock: AesSecureRandom

    @MockK
    private lateinit var aesBufferCipherMock: AesBufferCipher

    private val base64Engine = Base64Factory.createEngine()
    private val aesKey = AesKey(base64Engine.decode(ENCRYPTION_KEY_B64))
    private val iv = IV(base64Engine.decode(IV_B64))
    private val aesKeyIv = AesKeyIv(iv, aesKey)

    private val msgPlain = MESSAGE_LONG.encodeToByteArray()
    private val msgEncrypted = MESSAGE_LONG_ENCRYPTED_B64.encodeToByteArray()

    private val encryptedData = AesEncryptedData(iv, aesKey, msgEncrypted)

    @BeforeTest
    fun setUp() {
        MockKAnnotations.init(this)

        engine = AesBufferEngine(
                Aes256,
                CBC,
                PKCS7,
                inputChecksMock,
                randomGeneratorMock,
                aesBufferCipherMock)

        every { randomGeneratorMock.generateAesKey() } returns aesKey
        every { randomGeneratorMock.generateIv() } returns iv
        every { randomGeneratorMock.generateAesKeyAndIv() } returns aesKeyIv

        every { inputChecksMock.validateAesKey(aesKey) } returns Unit
        every { inputChecksMock.validateIv(iv) } returns Unit

        every { aesBufferCipherMock.encrypt(msgPlain,iv.data,aesKey.material) } returns msgEncrypted
        every { aesBufferCipherMock.decrypt(msgEncrypted,iv.data,aesKey.material) } returns msgPlain
    }

    @Test
    fun givenEncryptPlainData_andNoKeyOrIv_thenKeyIvEncryptedDataGenerated() {

        engine.encrypt(msgPlain)

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify { aesBufferCipherMock.encrypt(msgPlain,iv.data,aesKey.material) }

        verify { randomGeneratorMock.generateAesKeyAndIv() }
    }

    @Test
    fun givenEncryptPlainData_andCheckInvalidIv_thenThrowAesInvalidIvException() {
        every { inputChecksMock.validateIv(iv) } throws AesInvalidIvException("invalid IV")

        assertFailsWith(AesInvalidIvException::class) {
            engine.encrypt(msgPlain)
        }

        verify { inputChecksMock.validateIv(iv) }

        verify(exactly = 0) { inputChecksMock.validateAesKey(aesKey) }
        verify(exactly = 0) { aesBufferCipherMock.encrypt(msgPlain,iv.data,aesKey.material) }

        verify { randomGeneratorMock.generateAesKeyAndIv() }
    }

    @Test
    fun givenEncryptPlainData_andCheckInvalidAesKey_thenThrowAesInvalidKeyException() {
        every { inputChecksMock.validateAesKey(aesKey) } throws AesInvalidKeyException("invalid AesKey")

        assertFailsWith(AesInvalidKeyException::class) {
            engine.encrypt(msgPlain)
        }

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify(exactly = 0) { aesBufferCipherMock.encrypt(msgPlain,iv.data,aesKey.material) }

        verify { randomGeneratorMock.generateAesKeyAndIv() }
    }

    @Test
    fun givenEncryptPlainData_andKeySubmitted_thenIvEncryptedDataGenerated() {
        engine.encrypt(aesKey, msgPlain)

        verify { randomGeneratorMock.generateIv() }
        verify(exactly = 0) { randomGeneratorMock.generateAesKey() }

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify { aesBufferCipherMock.encrypt(msgPlain,iv.data,aesKey.material) }
    }

    @Test
    fun givenEncryptPlainData_andInvalidIv_thenThrowAesInvalidIvException() {
        every { inputChecksMock.validateIv(iv) } throws AesInvalidIvException("invalid IV")

        assertFailsWith(AesInvalidIvException::class) {
            engine.encrypt(aesKey, msgPlain)
        }

        verify { randomGeneratorMock.generateIv() }
        verify { inputChecksMock.validateIv(iv) }
        verify(exactly = 0) { randomGeneratorMock.generateAesKey() }

        verify(exactly = 0) { inputChecksMock.validateAesKey(aesKey) }
        verify(exactly = 0) { aesBufferCipherMock.encrypt(msgPlain,iv.data,aesKey.material) }
    }

    @Test
    fun givenEncryptPlainData_andKeyIvSubmitted_thenKeyIvEncryptedDataGenerated() {
        engine.encrypt(aesKeyIv, msgPlain)

        verify(exactly = 0) { randomGeneratorMock.generateIv() }
        verify(exactly = 0) { randomGeneratorMock.generateAesKey() }

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify { aesBufferCipherMock.encrypt(msgPlain,iv.data,aesKey.material) }
    }

    @Test
    fun givenDecryptEncryptedData_andCorrectParams_thenReturnDecryptedData() {
        engine.decrypt(encryptedData)

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }

        verify { aesBufferCipherMock.decrypt(msgEncrypted,iv.data,aesKey.material) }
    }

    @Test
    fun givenDecryptEncryptedData_andInavlidIv_thenThrowAesInvalidIvException() {
        every { inputChecksMock.validateIv(iv) } throws AesInvalidIvException("invalid IV")

        assertFailsWith(AesInvalidIvException::class) {
            engine.decrypt(encryptedData)
        }

        verify { inputChecksMock.validateIv(iv) }

        verify(exactly = 0) { inputChecksMock.validateAesKey(aesKey) }
        verify(exactly = 0) { aesBufferCipherMock.decrypt(msgEncrypted,iv.data,aesKey.material) }
    }

    @Test
    fun givenDecryptEncryptedData_andInavlidAesKey_thenThrowAesInvalidKeyException() {
        every { inputChecksMock.validateAesKey(aesKey) } throws AesInvalidKeyException("invalid key")

        assertFailsWith(AesInvalidKeyException::class) {
            engine.decrypt(encryptedData)
        }

        verify(exactly = 0) { aesBufferCipherMock.decrypt(msgEncrypted,iv.data,aesKey.material) }

        verify { inputChecksMock.validateIv(iv) }
        verify { inputChecksMock.validateAesKey(aesKey) }
    }
}