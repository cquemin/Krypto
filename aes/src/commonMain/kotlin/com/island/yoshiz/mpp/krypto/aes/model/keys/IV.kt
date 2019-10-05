package com.island.yoshiz.mpp.krypto.aes.model.keys

// Use for initialisation vector
data class IV(val data: ByteArray) {

    constructor(size: Int) : this(ByteArray(size))

    val size: Int
        get() = data.size

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IV

        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        return data.contentHashCode()
    }
}

inline fun IV.all(predicate: (Byte) -> Boolean): Boolean {
    for (element in this.data) if (!predicate(element)) return false
    return true
}
