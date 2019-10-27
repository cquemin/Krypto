package com.island.yoshiz.mpp.krypto.aes.model.config

/**
 * When it comes to AES and DES with CBC, PKCS5 and PKCS7 are inter exchangeable. Since PKCS5 is a
 * subset of PKCS7 if a platform support PKCS7 it also supports PKCS5 and considering that
 * AES (and DES and blowfish) are using using a block size of 8bytes e.g what PKCS5 has been defined
 * for. For those mode using one or the other does not matter.
 * see: https://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding
 */
internal enum class Padding {

    PKCS5, // Legacy, should not be used be used with AES but OK if you have to
    PKCS7
}