package com.island.yoshiz.mpp.krypto.common.model.streams

import com.island.yoshiz.mpp.krypto.common.NativeCipher

/**
 * Provides the ability to read and decrypt, via the cipher, the content of this stream
 */
internal class CipherInputStream(
        private val stream: InputStream,
        private val cipher: NativeCipher
) : InputStream() {

    override fun read(buffer: ByteArray): Int {
        val temp = ByteArray(buffer.size)
        var read = stream.read(temp)

        if (read > 0) {

            var decipheredData = ByteArray(0)
            val requiredLength = cipher.getOutputSize(read)
            var totalDeciphered = 0

            // Update while what is deciphered is still not the length of what has been read
            var buf = cipher.update(temp, 0, requiredLength)
            decipheredData += buf
            totalDeciphered += buf.size

            // If here update returns an empty array and the size is still not correct => call finalise
            buf = cipher.finalise()
            decipheredData += buf
            totalDeciphered += buf.size

            // return exactly deciphered data up to the size of the submitted buffer or totalDeciphered
            // whichever is the smallest
            decipheredData.copyInto(buffer, 0, 0, totalDeciphered)
            read = totalDeciphered
        }

        return read
    }

    override fun close() {
        stream.close()
    }
}