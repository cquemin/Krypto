package com.island.yoshiz.mpp.krypto.common.utils.extensions

fun String.asciiToByteArray() = ByteArray(length) {
    get(it).toByte()
}