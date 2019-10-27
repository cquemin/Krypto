package com.island.yoshiz.mpp.krypto.aes.engines

import com.island.yoshiz.mpp.krypto.aes.checks.AesInputSanityCheck
import com.island.yoshiz.mpp.krypto.aes.checks.AesInputSanityCheckNotSecure
import com.island.yoshiz.mpp.krypto.aes.model.config.AesConfiguration

/**
 * Entry point to generate [AesBufferEngine] or [AesFileEngine] from an [AesConfiguration].
 * Non secure variant avoid exception throwing if IV are zeroed. This is provided only for legacy
 * code compatibility
 */
class AesEngineFactory {

    fun getAesBufferEngine(configuration: AesConfiguration): AesBufferEngine {
        return AesBufferEngine(
                configuration.keyLength,
                configuration.mode,
                configuration.padding,
                AesInputSanityCheck(configuration.mode)
        )
    }

    fun getNonSecureAesBufferEngine(configuration: AesConfiguration): AesBufferEngine {
        return AesBufferEngine(
                configuration.keyLength,
                configuration.mode,
                configuration.padding,
                AesInputSanityCheckNotSecure(configuration.mode)
        )
    }

    fun getAesFileEngine(configuration: AesConfiguration): AesFileEngine {
        return AesFileEngine(
                configuration.keyLength,
                configuration.mode,
                configuration.padding,
                AesInputSanityCheck(configuration.mode)
        )
    }

    fun getNonSecureAesFileEngine(configuration: AesConfiguration): AesBufferEngine {
        return AesBufferEngine(
                configuration.keyLength,
                configuration.mode,
                configuration.padding,
                AesInputSanityCheckNotSecure(configuration.mode)
        )
    }
}