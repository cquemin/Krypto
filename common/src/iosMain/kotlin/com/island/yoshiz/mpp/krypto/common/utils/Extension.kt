package com.island.yoshiz.mpp.krypto.common.utils

import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import kotlinx.cinterop.toCValues
import platform.Foundation.NSData
import platform.Foundation.create
import platform.posix.memcpy

@ExperimentalUnsignedTypes
fun NSData.toByteArray(): ByteArray = memScoped {
    if (length.toInt() == 0) {
        return@memScoped ByteArray(0)
    }

    val nsData = ByteArray(length.convert())
    memcpy(nsData.refTo(0), bytes, length.convert())
    return nsData
}

fun ByteArray.toNSData(): NSData = memScoped {
    return NSData.create(
            bytes = toCValues().getPointer(this),
            length = size.convert()
    )
}