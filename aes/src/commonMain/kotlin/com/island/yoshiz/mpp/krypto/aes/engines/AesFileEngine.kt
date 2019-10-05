package com.island.yoshiz.mpp.krypto.aes.engines

import com.island.yoshiz.mpp.krypto.aes.checks.AesSanityChecks
import com.island.yoshiz.mpp.krypto.aes.ciphers.AesFileCipher
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength
import com.island.yoshiz.mpp.krypto.aes.model.config.Padding
import com.island.yoshiz.mpp.krypto.aes.model.file.AesDecryptedFileAndIV
import com.island.yoshiz.mpp.krypto.aes.model.file.AesEncryptedFile
import com.island.yoshiz.mpp.krypto.aes.model.file.AesEncryptedFileAndIV
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKey
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKeyIv
import com.island.yoshiz.mpp.krypto.aes.model.keys.IV
import com.island.yoshiz.mpp.krypto.aes.random.AesSecureRandom

/**
 * Offers several way to encrypt data. The recommended way would be to let this class generate the IV
 * for you which will be returned as a result of the encrypted data. Offers as well ways to decrypt
 */
class AesFileEngine internal constructor(
        keyLength: AesKeysLength,
        mode: AesBlockMode,
        padding: Padding?,
        private val inputChecks: AesSanityChecks,
        private val secureGenerator: AesSecureRandom = AesSecureRandom(keyLength, mode),
        private val fileCipher: AesFileCipher = AesFileCipher(keyLength, mode, padding)
) {


    /**
     * Encrypt the file with AES. Will securely generate an AES key of the right length and an IV of
     * the correct length
     *
     * @param pathToFile the full path of the file to encrypt
     * @param replaceOriginal true for the encrypted file to replace the original one
     * @return the key, iv and the path to the encrypted file
     */
    fun encrypt(pathToFile: String, replaceOriginal: Boolean = true): AesEncryptedFileAndIV {
        val keyIv = secureGenerator.generateAesKeyAndIv()
        return encrypt(keyIv, pathToFile, replaceOriginal)
    }

    /**
     * Encrypt the file with AES from the key submitted. It will securely generate an IV of the
     * right length
     *
     * @param key           the key for the encryption
     * @param pathToFile the full path of the file to encrypt
     * @param replaceOriginal true for the encrypted file to replace the original one
     * @return the key, iv and the path to the encrypted file
     */
    fun encrypt(
            key: AesKey, pathToFile: String, replaceOriginal: Boolean = true
    ): AesEncryptedFileAndIV {
        val iv = secureGenerator.generateIv()
        return encrypt(AesKeyIv(iv, key), pathToFile, replaceOriginal)
    }

    /**
     * This method is discouraged to use. It is kept for legacy purpose where you might need to
     * decrypt the data manually and the use the method where either the IV [encrypt] or both the
     * key and IV [encrypt] are generated for you.
     */
    fun encrypt(
            keyIv: AesKeyIv, pathToFile: String, replaceOriginal: Boolean = true
    ): AesEncryptedFileAndIV {
        validateInputs(keyIv.aesKey, keyIv.iv)

        val encryptedFilePath = fileCipher.encrypt(
                pathToFile,
                keyIv.iv.data,
                keyIv.aesKey.material,
                replaceOriginal,
                expectIvInFile = false
        )

        return AesEncryptedFileAndIV(keyIv, encryptedFilePath)
    }

    /**
     * Encrypt the file with AES. Will securely generate an AES key of the right length and an IV of
     * the correct length
     *
     * @param pathToFile the full path of the file to encrypt
     * @param replaceOriginal true for the encrypted file to replace the original one
     * @return the key, iv and the path to the encrypted file
     */
    fun encryptAddIv(pathToFile: String, replaceOriginal: Boolean = true): AesEncryptedFile {
        val keyIv = secureGenerator.generateAesKeyAndIv()
        return encryptAddIv(keyIv, pathToFile, replaceOriginal)
    }

    /**
     * Encrypt the file with AES from the key submitted. It will securely generate an IV of the
     * right length
     *
     * @param key           the key for the encryption
     * @param pathToFile the full path of the file to encrypt
     * @param replaceOriginal true for the encrypted file to replace the original one
     * @return the key, iv and the path to the encrypted file
     */
    fun encryptAddIv(
            key: AesKey, pathToFile: String, replaceOriginal: Boolean = true
    ): AesEncryptedFile {
        val iv = secureGenerator.generateIv()
        return encryptAddIv(AesKeyIv(iv, key), pathToFile, replaceOriginal)
    }

    /**
     * This method is discouraged to use. It is kept for legacy purpose where you might need to
     * decrypt the data manually and the use the method where either the IV [encrypt] or both the
     * key and IV [encrypt] are generated for you.
     */
    fun encryptAddIv(
            keyIv: AesKeyIv, pathToFile: String, replaceOriginal: Boolean = true
    ): AesEncryptedFile {
        validateInputs(keyIv.aesKey, keyIv.iv)

        val encryptedFilePath = fileCipher.encrypt(
                pathToFile,
                keyIv.iv.data,
                keyIv.aesKey.material,
                replaceOriginal,
                expectIvInFile = false
        )

        return AesEncryptedFile(keyIv.aesKey, encryptedFilePath)
    }

    /**
     * Encrypt the file with AES. Will securely generate an AES key of the right length and an IV of
     * the correct length
     *
     * @param pathToFile the full path of the file to encrypt
     * @param replaceOriginal true for the encrypted file to replace the original one
     * @return the key, iv and the path to the encrypted file
     */
    fun encryptAddAndPersistIv(
            pathToFile: String, replaceOriginal: Boolean = true
    ): AesEncryptedFile {
        val keyIv = secureGenerator.generateAesKeyAndIv()
        return encryptAddIv(keyIv, pathToFile, replaceOriginal)
    }

    /**
     * Encrypt the file with AES from the key submitted. It will securely generate an IV of the
     * right length
     *
     * @param key           the key for the encryption
     * @param pathToFile the full path of the file to encrypt
     * @param replaceOriginal true for the encrypted file to replace the original one
     * @return the key, iv and the path to the encrypted file
     */
    fun encryptAddAndPersistIv(
            key: AesKey, pathToFile: String, replaceOriginal: Boolean = true
    ): AesEncryptedFile {
        val iv = secureGenerator.generateIv()
        return encryptAddIv(AesKeyIv(iv, key), pathToFile, replaceOriginal)
    }

    /**
     * This method is discouraged to use. It is kept for legacy purpose where you might need to
     * decrypt the data manually and the use the method where either the IV [encrypt] or both the
     * key and IV [encrypt] are generated for you.
     */
    fun encryptAddAndPersistIv(
            keyIv: AesKeyIv, pathToFile: String, replaceOriginal: Boolean = true
    ): AesEncryptedFile {
        validateInputs(keyIv.aesKey, keyIv.iv)

        val encryptedFilePath = fileCipher.encrypt(
                pathToFile,
                keyIv.iv.data,
                keyIv.aesKey.material,
                replaceOriginal,
                expectIvInFile = true
        )

        return AesEncryptedFile(keyIv.aesKey, encryptedFilePath)
    }

    /**
     * Decrypt the data with the submitted key and iv
     *
     * @param fileToDecrypt the encrypted data to decrypt and the IV
     * @return decrypted data
     */
    fun decrypt(
            fileToDecrypt: AesEncryptedFileAndIV, replaceOriginal: Boolean
    ): AesDecryptedFileAndIV {
        validateInputs(fileToDecrypt.keyIv.aesKey, fileToDecrypt.keyIv.iv)

        val path = fileCipher.decrypt(
                fileToDecrypt.pathToFile,
                fileToDecrypt.keyIv.iv.data,
                fileToDecrypt.keyIv.aesKey.material,
                replaceOriginal,
                expectIvInFile = false
        )
        return AesDecryptedFileAndIV(fileToDecrypt.keyIv, path)
    }

    /**
     * Decrypt the data with the submitted key and iv
     *
     * @param fileToDecrypt the encrypted data to decrypt and the IV
     * @return decrypted data
     */
    fun decryptWithIvFromFile(
            fileToDecrypt: AesEncryptedFileAndIV, replaceOriginal: Boolean
    ): AesDecryptedFileAndIV {
        validateInputs(fileToDecrypt.keyIv.aesKey, fileToDecrypt.keyIv.iv)

        val path = fileCipher.decrypt(
                fileToDecrypt.pathToFile,
                fileToDecrypt.keyIv.iv.data,
                fileToDecrypt.keyIv.aesKey.material,
                replaceOriginal,
                expectIvInFile = true
        )
        return AesDecryptedFileAndIV(fileToDecrypt.keyIv, path)
    }

    private fun validateInputs(aesKey: AesKey, iv: IV) {
        inputChecks.validateIv(iv)
        inputChecks.validateAesKey(aesKey)
    }
}

