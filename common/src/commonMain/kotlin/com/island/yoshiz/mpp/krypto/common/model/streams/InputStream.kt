package com.island.yoshiz.mpp.krypto.common.model.streams

/**
 * Ability to [read] and [close] a stream of data could be a buffer or a file or anything else.
 */
expect abstract class InputStream() {

    /*
     * The content of the underlying stream will be read and put in the [buffer]
     * @returns the number of bytes read, -1 if there is no more byte to read
     */
    open fun read(buffer: ByteArray): Int

    open fun close()
}


