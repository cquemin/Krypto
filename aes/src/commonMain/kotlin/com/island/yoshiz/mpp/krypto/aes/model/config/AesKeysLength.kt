package com.island.yoshiz.mpp.krypto.aes.model.config

internal enum class AesKeysLength(val lengthBits: Int) {
    Aes128(128),
    Aes192(192),
    Aes256(256);

    val lengthBytes: Int = lengthBits / 8
}