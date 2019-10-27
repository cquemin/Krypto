package com.island.yoshiz.mpp.krypto.common.model.streams

import com.island.yoshiz.mpp.krypto.common.model.exceptions.InputStreamException
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import platform.Foundation.NSInputStream
import platform.posix.memcpy
import platform.posix.uint8_tVar

/**
 * Ability to [read] and [close] a stream of data could be a buffer or a file or anything else.
 */
actual abstract class InputStream {

    protected lateinit var inputStream: NSInputStream

    actual open fun read(buffer: ByteArray): Int = memScoped {
        val bufferSize = buffer.size
        val readBuffer = allocArray<uint8_tVar>(bufferSize.convert())

        val dataReadCount = inputStream.read(readBuffer, bufferSize.convert())

        if (dataReadCount > 0) {
            memcpy(buffer.refTo(0), readBuffer, dataReadCount.convert())
        } else if (dataReadCount == -1L) {
            throw InputStreamException("Unable to read the given stream: ${inputStream.streamError?.localizedDescription}")
        }

        return@memScoped dataReadCount.toInt()
    }

    actual open fun close() {
        inputStream.close()
    }
}