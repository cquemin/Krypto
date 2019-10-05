package com.island.yoshiz.mpp.krypto.aes.model.file

import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKeyIv

data class AesDecryptedFileAndIV(
        val keyIv: AesKeyIv,
        val pathToFile: String
)
