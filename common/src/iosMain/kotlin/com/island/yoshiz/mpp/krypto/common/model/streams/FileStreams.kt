package com.island.yoshiz.mpp.krypto.common.model.streams

import com.island.yoshiz.mpp.krypto.common.model.files.File
import platform.Foundation.NSInputStream
import platform.Foundation.NSOutputStream
import platform.Foundation.inputStreamWithFileAtPath
import platform.Foundation.outputStreamToFileAtPath

actual class FileInputStream actual constructor(file: File) : InputStream() {
    init {
        inputStream = NSInputStream.inputStreamWithFileAtPath(file.getAbsolutePath())!!
        inputStream.open()
    }
}

actual class FileOutputStream actual constructor(file: File) : OutputStream() {
    init {
        outputStream = NSOutputStream.outputStreamToFileAtPath(file.getAbsolutePath(), false)
        outputStream.open()
    }
}