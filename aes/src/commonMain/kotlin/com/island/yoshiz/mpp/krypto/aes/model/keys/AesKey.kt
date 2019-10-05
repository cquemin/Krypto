package com.island.yoshiz.mpp.krypto.aes.model.keys

/**
 * Used to submit the key required for aes encryption operation. This is the recommended way
 * to request for AES encryption as the Initialisation vector will be generated securely in the library
 */
data class AesKey(val material: ByteArray) {

    val size: Int
        get() = material.size

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AesKey

        if (!material.contentEquals(other.material)) return false

        return true
    }

    override fun hashCode(): Int {
        return material.contentHashCode()
    }
}

inline fun AesKey.all(predicate: (Byte) -> Boolean): Boolean {
    for (element in this.material) if (!predicate(element)) return false
    return true
}