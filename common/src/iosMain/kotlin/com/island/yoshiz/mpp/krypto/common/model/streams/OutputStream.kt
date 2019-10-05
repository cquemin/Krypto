package com.island.yoshiz.mpp.krypto.common.model.streams

import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import platform.Foundation.NSOutputStream
import platform.posix.memcpy
import platform.posix.uint8_tVar

/**
 * Provides the ability to encrypt and write to the stream via the cipher
 */
actual abstract class OutputStream {

    protected lateinit var outputStream: NSOutputStream

    /**
     * write the content of [buffer] in the underlying stream
     */
    actual open fun write(buffer: ByteArray, offset: Int, size: Int) = memScoped {
        val bufferSize = buffer.size

        if (bufferSize > 0) {
            val writeBuffer = allocArray<uint8_tVar>(bufferSize.convert())
            memcpy(writeBuffer, buffer.refTo(0), bufferSize.convert())

            outputStream.write(writeBuffer, size.convert())
        }
    }

    actual open fun flush() {
        //nothing to do here
    }

    actual open fun close() {
        outputStream.close()
    }
}