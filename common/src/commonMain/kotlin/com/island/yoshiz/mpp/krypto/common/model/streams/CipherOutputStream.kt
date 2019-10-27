package com.island.yoshiz.mpp.krypto.common.model.streams

import com.island.yoshiz.mpp.krypto.common.NativeCipher

/**
 * Provides the ability to encrypt, via the cipher, and write the content of this stream
 */
internal class CipherOutputStream(
        private val stream: OutputStream,
        private val cipher: NativeCipher
) : OutputStream() {

    override fun write(buffer: ByteArray, offset: Int, size: Int) {
        val result = cipher.update(buffer, offset, size)
        if (result.isNotEmpty()) {
            stream.write(result, offset, result.size)
        }
    }

    override fun flush() {
        val result = cipher.finalise()
        if (result.isNotEmpty()) {
            stream.write(result, 0, result.size)
        }
        stream.flush()
    }

    override fun close() {
        stream.close()
    }
}