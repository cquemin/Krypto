package com.island.yoshiz.mpp.krypto.common.model.streams

typealias JavaOutputStream = java.io.OutputStream

actual abstract class OutputStream {
    protected lateinit var outputStream: JavaOutputStream

    /**
     * write the content of [buffer] in the underlying stream
     * @param offset - offset is ignored
     * @param size - the size to write from the submitted [buffer]
     */
    actual open fun write(buffer: ByteArray, offset: Int, size: Int) {
        outputStream.write(buffer, offset, size)
    }

    actual open fun flush() {
        outputStream.flush()
    }

    actual open fun close() {
        outputStream.close()
    }
}

