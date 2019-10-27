package com.island.yoshiz.mpp.krypto.aes.ciphers

import com.island.yoshiz.mpp.krypto.aes.model.config.AesBlockMode
import com.island.yoshiz.mpp.krypto.aes.model.config.AesKeysLength
import com.island.yoshiz.mpp.krypto.aes.model.config.Padding
import com.island.yoshiz.mpp.krypto.common.NativeCipher

/**
 * This class will be implementing the native cryptographic function for each platform
 */
internal expect class AesNativeCipher(
        keyLength: AesKeysLength,
        mode: AesBlockMode,
        padding: Padding?
) : NativeCipher
