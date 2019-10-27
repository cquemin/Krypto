package com.island.yoshiz.mpp.krypto.aes.model.file

import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKey
import com.island.yoshiz.mpp.krypto.aes.model.keys.AesKeyIv

data class AesEncryptedFileAndIV(
        val keyIv: AesKeyIv,
        val pathToFile: String
)

data class AesEncryptedFile(
        val key: AesKey,
        val pathToFile: String
)