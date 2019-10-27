package com.island.yoshiz.mpp.krypto.aes.model.buffer

import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKey
import com.island.yoshiz.mpp.krypto.aes.model.keys.IV

data class AesEncryptedDataIv(val iv: IV, val encryptedData: ByteArray) {

    /**
     * Assumes that the first byte contains the size of the IV field and that the rest of the
     * array is the encrypted data
     */
    constructor(data: ByteArray) : this(
            IV(data.sliceArray(0 until data[0])),
            data.sliceArray(data[0] until data.size)
    )

    /**
     *
     * @return an array with in this order :
     * - the iv length on one byte
     * - the iv data
     * - the encrypted data
     */
    fun toByteArray(): ByteArray {
        return byteArrayOf(iv.size.toByte()) + iv.data + encryptedData
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AesEncryptedDataIv

        if (iv != other.iv) return false
        if (!encryptedData.contentEquals(other.encryptedData)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = iv.hashCode()
        result = 31 * result + encryptedData.contentHashCode()
        return result
    }
}

/**
 * Data returned by encryption method and data to submit to decryption method
 * This contains the IV, the AES key used for the encryption operation and the encrypted data itself.
 * It is recommended to use [encryptedDataIv] value for further manipulation. As this will create
 * a [ByteArray] where the iv length, the IV and the encrypted data are concatenated.
 */
data class AesEncryptedData(
        val iv: IV,
        val aesKey: AesKey,
        val encryptedData: ByteArray
) {

    /**
     * Consider that [encryptedDataIv] is encoded the same way [encryptedDataIv] does
     */
    constructor(key: AesKey, encryptedDataIv: AesEncryptedDataIv) : this(
            encryptedDataIv.iv, key, encryptedDataIv.encryptedData
    )

    /**
     *
     * Return in this order :
     * - the iv length on one byte
     * - the iv data
     * - the encrypted data
     */
    val encryptedDataIv = AesEncryptedDataIv(iv, encryptedData).toByteArray()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AesEncryptedData

        if (iv != other.iv) return false
        if (aesKey != other.aesKey) return false
        if (!encryptedData.contentEquals(other.encryptedData)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = iv.hashCode()
        result = 31 * result + aesKey.hashCode()
        result = 31 * result + encryptedData.contentHashCode()
        return result
    }
}