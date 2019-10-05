package com.island.yoshiz.mpp.krypto.aes.model

import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKeyIv

data class AesDecryptedFileAndIV(
        val keyIv: AesKeyIv,
        val pathToFile: String
)
