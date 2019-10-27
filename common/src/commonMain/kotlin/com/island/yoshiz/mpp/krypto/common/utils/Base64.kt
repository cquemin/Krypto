package com.island.yoshiz.mpp.krypto.common.utils

interface Base64Engine {
    fun encode(src: ByteArray): ByteArray
    fun decode(src: ByteArray): ByteArray

    @ExperimentalStdlibApi
    fun encode(src: String) = encode(src.encodeToByteArray())

    @ExperimentalStdlibApi
    fun decode(src: String) = decode(src.encodeToByteArray())
}

expect object Base64Factory {
    fun createEngine(): Base64Engine
}