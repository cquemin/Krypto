package com.island.yoshiz.mpp.krypto.aes.ciphers

import com.island.yoshiz.mpp.krypto.aes.model.buffer.AesEncryptedData
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength
import com.island.yoshiz.mpp.krypto.aes.model.config.Padding
import com.island.yoshiz.mpp.krypto.aes.model.exceptions.AesException
import com.island.yoshiz.mpp.krypto.common.Operation
import com.island.yoshiz.mpp.krypto.common.Operation.DECRYPT
import com.island.yoshiz.mpp.krypto.common.Operation.ENCRYPT
import com.island.yoshiz.mpp.krypto.common.model.files.File
import com.island.yoshiz.mpp.krypto.common.model.streams.InputStream
import com.island.yoshiz.mpp.krypto.common.model.streams.OutputStream
import com.island.yoshiz.mpp.krypto.common.utils.getInputStreamForCipher
import com.island.yoshiz.mpp.krypto.common.utils.getOutputStream
import com.island.yoshiz.mpp.krypto.common.utils.getOutputStreamForCipher
import com.island.yoshiz.mpp.krypto.common.utils.getTempFileName

/**
 * Implements the actual operation of encryption and decryption for AES transformation on a file.
 * The underlying AES transformation is delegated to an [AesNativeCipher] instance
 */
internal class AesFileCipher constructor(
        keyLength: AesKeysLength,
        private val mode: AesBlockMode,
        padding: Padding?
) {

    private var cipher = AesNativeCipher(keyLength, mode, padding)

    /**
     * Performs the AES decryption according to parameters passed at construction time
     * This consider that the content of [pathToFile] is valid. Checks must be performed before
     * this method is called.
     *
     * @param pathToFile the path to the file to decrypt
     * @param iv the initialisation vector
     * @param aesKey the encryption key material
     * @param replaceOriginal true: the original file located at [pathToFile] will be replaced with
     * its decrypted version. False, the original file will be kept unchanged.
     * @param expectIvInFile true if the IV is expected to be in the encrypted file. If so it will be persisted
     * at the beginning: $ivSize $iv $encryptedFileContent
     * @return the path to the decrypted file. if [replaceOriginal] is true, this will the same
     * value as [pathToFile]
     */
    fun decrypt(
            pathToFile: String,
            iv: ByteArray,
            aesKey: ByteArray,
            replaceOriginal: Boolean,
            expectIvInFile: Boolean
    ): String {
        return performFileOperation(
                pathToFile,
                iv,
                aesKey,
                DECRYPT,
                replaceOriginal,
                expectIvInFile
        )
    }

    /**
     * Performs the AES encryption according to parameters passed at construction time
     * This will return a valid instance of [AesEncryptedData]
     *
     * @param pathToFile the path to the file to encrypt
     * @param iv the initialisation vector
     * @param aesKey the encryption key material
     * @param replaceOriginal true: the original file located at [pathToFile] will be replaced with
     * its encrypted version. False, the original file will be kept unchanged.
     * @param expectIvInFile true if the IV is expected to be in the encrypted file. If so it will be persisted
     * at the beginning: $ivSize $iv $encryptedFileContent
     * @return the path to the encrypted file. if [replaceOriginal] is true, this will the same
     * value as [pathToFile]
     */
    fun encrypt(
            pathToFile: String,
            iv: ByteArray,
            aesKey: ByteArray,
            replaceOriginal: Boolean,
            expectIvInFile: Boolean
    ): String {
        return performFileOperation(
                pathToFile,
                iv,
                aesKey,
                ENCRYPT,
                replaceOriginal,
                expectIvInFile
        )
    }

    private fun performFileOperation(
            pathToFile: String,
            iv: ByteArray?,
            key: ByteArray,
            operation: Operation,
            replaceOriginal: Boolean,
            expectIvInFile: Boolean
    ): String {

        var inputStream: InputStream? = null
        var outputStream: OutputStream? = null
        var actualIv = iv

        val tempFilePath = getTempFileName(pathToFile, operation)

        val sourceFile = File(pathToFile)
        if (sourceFile.exists().not()) {
            throw AesException("The file '$pathToFile' doesn't exist, operation = $operation")
        }

        try {

            inputStream = getInputStreamForCipher(pathToFile, operation, cipher)
            outputStream = getOutputStreamForCipher(tempFilePath, operation, cipher)

            if (expectIvInFile) {
                // IV needs to be written in clear
                actualIv =
                        processExpectedIvInFile(operation, actualIv, tempFilePath, inputStream)
            }

            // Cipher needs to be properly initialised before(!) starting to use it
            cipher.init(actualIv!!, key, operation)

            readWriteCipheredStream(inputStream, outputStream)

            // Delete clear file, and renamed encrypted to the old file name
            val destinationFile = File(tempFilePath)
            return if (replaceOriginal) {

                replaceSourceFile(sourceFile, destinationFile)
            } else {
                destinationFile.getAbsolutePath()
            }
        } finally {
            inputStream?.close()
            outputStream?.close()
        }
    }

    private fun readWriteCipheredStream(inputStream: InputStream, outputStream: OutputStream) {
        val buffer = ByteArray(1024 * 1024)

        // Loop that will read from the input stream and then write to the output stream
        var read = inputStream.read(buffer)
        while (read > 0) {

            outputStream.write(buffer, 0, read)

            // read next chunk from the file
            read = inputStream.read(buffer)
        }

        outputStream.flush()
    }

    /**
     * @param operation the current operation : [ENCRYPT] or [DECRYPT]
     * @param iv in case of an [ENCRYPT] operation and the IV is
     * expected to be NON null and will be written in [filePathToWriteTo]. If the operation is
     * [DECRYPT] the iv will be read from the [inputStream]
     */
    private fun processExpectedIvInFile(
            operation: Operation,
            iv: ByteArray?,
            filePathToWriteTo: String,
            inputStream: InputStream
    ): ByteArray? {
        var actualIv = iv

        if (operation == ENCRYPT) {
            val clearOutputStream = getOutputStream(filePathToWriteTo)
            clearOutputStream.write(iv!!, 0, iv.size)
            clearOutputStream.flush()
            clearOutputStream.close()
        } else if (operation == DECRYPT) {
            actualIv = ByteArray(mode.ivLengthBytes)
            inputStream.read(actualIv)
        }

        return actualIv
    }

    /**
     * Replace [source] with [destination] and returns the path of the new file which is now source
     */
    private fun replaceSourceFile(source: File, destination: File): String {
        // Delete clear file, and renamed encrypted to the old file name

        if (!source.delete()) {
            throw AesException("Unable to remove ${source.getAbsolutePath()}")
        }

        if (!destination.renameTo(source)) {
            throw AesException(
                    "Unable to move the destination file from '${source.getAbsolutePath()}' to " +
                            "'${destination.getAbsolutePath()}'"
            )
        }

        return source.getAbsolutePath()
    }
}

private const val TAG = "FileCipher"