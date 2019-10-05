package com.island.yoshiz.mpp.krypto.aes.model.config

import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CBC
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.CTR
import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode.GCM
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes128
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes192
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength.Aes256
import com.island.yoshiz.mpp.krypto.aes.model.config.Padding.PKCS7

enum class AesConfiguration(
        internal val keyLength: AesKeysLength,
        internal val mode: AesBlockMode,
        internal val padding: Padding?
) {

    AES_CBC_PKCS7_256(Aes256, CBC, PKCS7),
    AES_CBC_PKCS7_192(Aes192, CBC, PKCS7),
    AES_CBC_PKCS7_128(Aes128, CBC, PKCS7),

    AES_CTR_PKCS7_256(Aes256, CTR, null),
    AES_CTR_PKCS7_192(Aes192, CTR, null),
    AES_CTR_PKCS7_128(Aes128, CTR, null),

    AES_GCM_PKCS7_256(Aes256, GCM, null),
    AES_GCM_PKCS7_192(Aes192, GCM, null),
    AES_GCM_PKCS7_128(Aes128, GCM, null)
}

/**
 * Secure vs No secure mode (S  vs NS)
 * ECB + data.length > 128bits => NS: warning, S: Exception
 * ECB + IV : illegal argument
 * DO NOT USE
 * ///====\\\
 *
 * CBC + no IV => use iv with 0 => NS: warning, S: Exception
 * CTR + IV : illegal argument
 *
 * AES + S , [prevent set of IV, generate one internally + return it]
 *
 * Enc + Auth : GCM (12 byte IV, rest is 16)
 * Enc then Mac : HMAC cipher text AND IV. Append to cipher text
 * HKDF for key used for MAC for AES + MAC
 * MAC allow associated data to be MAC'ed
 *
 * return ivLength, iv, cipherText
 * erase keys to zero
 *
 * ===
 *
 * Decrypt, validate iv length otherwise create out of memory
 *
 *
 * Secure mode + key monitoring and IV monitoring: IV never re used with same key
 */

/**
 * RSA : check that data length is small enough to be encrypted by the key
 * => the plain text data must be 130 bytes smaller than the key’s block size
 */

/**
 * AES
 * https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
 * https://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb
 * Android/java:
 * https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher
 * https://developer.android.com/guide/topics/security/cryptography
 */

/**
 * RSA
 * https://stackoverflow.com/questions/48958304/pkcs1-and-pkcs8-format-for-rsa-private-key
 * https://pasztor.at/blog/working-with-certificates-in-java
 * https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
 */
