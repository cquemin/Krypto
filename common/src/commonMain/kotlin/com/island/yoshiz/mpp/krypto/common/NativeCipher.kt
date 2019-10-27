package com.island.yoshiz.mpp.krypto.common

interface NativeCipher {
    /**
     * Initialise internal structures with the key and iv submitted
     * This method must be called first
     */
    fun init(iv: ByteArray, aesKey: ByteArray, operation: Operation)

    /**
     * Update the current cipher with the next bunch of data.
     * If the data length is less than the block size then the returned buffer will be empty
     */
    fun update(data: ByteArray, offset: Int, size: Int): ByteArray

    /**
     * Finalise a multipart operation. return the data left not returned by [update]
     */
    fun finalise(): ByteArray

    /**
     * return the size required to store the result of the next call to [update] or [finalise]
     */
    fun getOutputSize(inputLength: Int): Int
}