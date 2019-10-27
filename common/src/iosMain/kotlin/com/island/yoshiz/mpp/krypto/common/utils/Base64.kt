package com.island.yoshiz.mpp.krypto.common.utils

import kotlinx.cinterop.convert
import platform.Foundation.NSData
import platform.Foundation.base64EncodedDataWithOptions
import platform.Foundation.create

actual object Base64Factory {
    actual fun createEngine(): Base64Engine = IOSBase64Engine
}

@ExperimentalUnsignedTypes
object IOSBase64Engine : Base64Engine {

    override fun decode(src: ByteArray):
            ByteArray = NSData.create(
            src.toNSData(), 0.convert()
    )!!.toByteArray()

    override fun encode(
            src: ByteArray
    ): ByteArray = src.toNSData().base64EncodedDataWithOptions(0.convert()).toByteArray()
}