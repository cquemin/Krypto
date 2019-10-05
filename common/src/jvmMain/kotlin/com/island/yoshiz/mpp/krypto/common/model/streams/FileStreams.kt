package com.island.yoshiz.mpp.krypto.common.model.streams

import com.island.yoshiz.mpp.krypto.common.model.files.File

typealias JavaFileInputStream = java.io.FileInputStream
typealias JavaFileOutputStream = java.io.FileOutputStream

actual class FileInputStream actual constructor(file: File) : InputStream() {
    init {
        inputStream = JavaFileInputStream(file)
    }
}

actual class FileOutputStream actual constructor(file: File) : OutputStream() {
    init {
        outputStream = JavaFileOutputStream(file)
    }
}