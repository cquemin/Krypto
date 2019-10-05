package com.island.yoshiz.mpp.krypto.common.utils

import java.util.Base64

actual object Base64Factory {
    actual fun createEngine(): Base64Engine = JvmBase64Engine
}

object JvmBase64Engine : Base64Engine {
    override fun decode(src: ByteArray): ByteArray = Base64.getDecoder().decode(src)

    override fun encode(src: ByteArray): ByteArray = Base64.getEncoder().encode(src)
}