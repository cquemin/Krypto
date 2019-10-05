package com.island.yoshiz.mpp.krypto.common.utils.extensions

fun ByteArray.byteToCharArray() = CharArray(size) {
    get(it).toChar()
}

/**
 * return a BigEndian bigEndianInteger built this way:
 * |---------------------------------------|
 * | byte[0] | byte[1] | byte[2] | byte[3] |
 * |_______________________________________|
 *
 * [ByteArray.size] must be between 0 and  [Int.SIZE_BYTES]
 */
fun ByteArray.toBigEndianInteger(): Int {
    require(this.size <= Int.SIZE_BYTES) {
        "This byte array must not be longer than ${Int.SIZE_BYTES}"
    }

    var bigEndian = 0

    this.reversedArray().forEachIndexed { index, byte ->
        bigEndian = bigEndian.buildFrom(byte, index)
    }

    return bigEndian
}

/**
 * return a LittleEndian bigEndianInteger built this way:
 * |---------------------------------------|
 * | byte[3] | byte[2] | byte[1] | byte[0] |
 * |_______________________________________|
 *
 * [ByteArray.size] must be between 0 and  [Int.SIZE_BYTES]
 */
fun ByteArray.toLittleEndianInteger(): Int {
    require(this.size <= Int.SIZE_BYTES) {
        "This byte array must not be longer than ${Int.SIZE_BYTES}"
    }

    var littleEndian = 0

    this.forEachIndexed { index, byte ->
        littleEndian = littleEndian.buildFrom(byte, index)
    }

    return littleEndian
}


