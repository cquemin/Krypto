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
