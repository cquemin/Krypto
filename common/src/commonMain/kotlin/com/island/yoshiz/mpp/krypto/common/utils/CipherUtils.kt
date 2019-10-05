package com.island.yoshiz.mpp.krypto.common.utils

import com.island.yoshiz.mpp.krypto.common.NativeCipher
import com.island.yoshiz.mpp.krypto.common.Operation
import com.island.yoshiz.mpp.krypto.common.Operation.DECRYPT
import com.island.yoshiz.mpp.krypto.common.Operation.ENCRYPT
import com.island.yoshiz.mpp.krypto.common.model.files.File
import com.island.yoshiz.mpp.krypto.common.model.streams.CipherInputStream
import com.island.yoshiz.mpp.krypto.common.model.streams.CipherOutputStream
import com.island.yoshiz.mpp.krypto.common.model.streams.FileInputStream
import com.island.yoshiz.mpp.krypto.common.model.streams.FileOutputStream
import com.island.yoshiz.mpp.krypto.common.model.streams.InputStream
import com.island.yoshiz.mpp.krypto.common.model.streams.OutputStream

const val ENCRYPTED_FILE_SUFFIX = "encrypted"
const val DECRYPTED_FILE_SUFFIX = "decrypted"

fun getTempFileName(original: String, operation: Operation): String {
    val tempFileExtension =
            if (operation == ENCRYPT) ENCRYPTED_FILE_SUFFIX else DECRYPTED_FILE_SUFFIX

    return "$original.$tempFileExtension"
}

/**
 * @return an input stream that points at [pathToFile]. If the [operation] is [ENCRYPT], the returned
 * stream will simply allow 'normal' read from the file. If the [operation] is [DECRYPT], the returned
 * stream will decrypt the content read from the file.
 */
fun getInputStreamForCipher(
        pathToFile: String, operation: Operation, cipher: NativeCipher
): InputStream {
    val sourceFile = File(pathToFile)
    val fileInputStream = FileInputStream(sourceFile)

    // for encrypt => we just read the original content: FileInputStream
    // for decrypt => we need to decrypt the read content: CipherInputStream
    return when (operation) {
        ENCRYPT -> fileInputStream
        DECRYPT -> CipherInputStream(fileInputStream, cipher)
    }
}

/**
 * @return an output stream that points at the value returned by[getTempFileName]. If the [operation] is [ENCRYPT], the returned
 * stream will encrypt the content before writing it to the file. If the [operation] is [DECRYPT], the returned
 * stream will simply allow 'normal' write from the file
 */
fun getOutputStreamForCipher(
        pathToFile: String, operation: Operation, cipher: NativeCipher
): OutputStream {
    val destinationFile = File(pathToFile)
    val fileOutputStream = FileOutputStream(destinationFile)

    // for encrypt => we need to encrypt what will be written: CipherOutputStream
    // for decrypt => the content has ben decrypted. We just write normally: FileOutputStream
    return when (operation) {
        ENCRYPT -> CipherOutputStream(fileOutputStream, cipher)
        DECRYPT -> fileOutputStream
    }
}

fun getOutputStream(pathToFile: String):OutputStream{
    val destinationFile = File(pathToFile)

    return FileOutputStream(destinationFile)
}