package com.island.yoshiz.mpp.krypto.aes.model.keys

/**
 * Since the way IV are generated is critical to how secure the encryption will be, passing
 * an IV for encryption method is deemed not secure. It is safer to let the library generating one
 * for you. this can be done via using [AesKey]
 * This data class should only be used for decryption operation or with a NON Secure engine.
 */
data class AesKeyIv(val iv: IV, val aesKey: AesKey) {

    internal constructor(iv: ByteArray, material: ByteArray) : this(IV(iv), AesKey(material))
    constructor(iv: IV, material: ByteArray) : this(iv, AesKey(material))
}


