package com.island.yoshiz.mpp.krypto.aes.model.exceptions

import com.island.yoshiz.mpp.krypto.common.model.exceptions.KryptoException

open class AesException(message: String? = null, cause: Throwable? = null) :
        KryptoException(message, cause)
