package com.island.yoshiz.mpp.krypto.common.model.streams

/**
 * Provides the ability to encrypt and write to the stream via the cipher
 */
expect abstract class OutputStream() {

    /**
     * write the content of [buffer] in the underlying stream
     * @param offset - offset is ignored
     * @param size - the size to write from the submitted [buffer]
     */
    open fun write(buffer: ByteArray, offset: Int, size: Int)

    open fun flush()

    open fun close()
}