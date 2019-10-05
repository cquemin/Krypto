package com.island.yoshiz.mpp.krypto.common.utils.extensions

import kotlin.experimental.and

/**
 * OR the byte to the submitted position in the current bigEndianInteger
 * if byte is 0xB and the current int (this) is 0xAAAA then:
 * 0xAAAA.buildFrom(0xB, 2) => 0xAABA.
 * Byte position must be between 0 and [Int.SIZE_BYTES]
 */
fun Int.buildFrom(byte: Byte, bytePosition: Int): Int {
    require(bytePosition <= Int.SIZE_BYTES) {
        "This byte position must be between 0 and ${Int.SIZE_BYTES}"
    }

    return this.or(byte.and(0xF).shl(bytePosition))
}
