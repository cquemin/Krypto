package com.island.yoshiz.mpp.krypto.common.utils.extensions

infix fun Byte.shr(bitCount: Int): Int {
    return this.toInt().shr(bitCount)
}

infix fun Byte.shl(bitCount: Int): Int {
    return this.toInt().shl(bitCount)
}
