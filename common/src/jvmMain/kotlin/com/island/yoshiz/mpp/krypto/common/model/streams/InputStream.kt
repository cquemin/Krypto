package com.island.yoshiz.mpp.krypto.common.model.streams

typealias JavaInputStream = java.io.InputStream

actual abstract class InputStream {
    protected lateinit var inputStream: JavaInputStream

    actual open fun read(buffer: ByteArray): Int {
        return inputStream.read(buffer)
    }

    actual open fun close() {
        inputStream.close()
    }
}