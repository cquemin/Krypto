package com.island.yoshiz.mpp.krypto.common.utils

/** MPP method only, use the version that takes Builder for client code */
actual fun logVerbose(tag: String, message: String) {
    println("VBZ - $tag : $message")
}

/** MPP method only, use the version that takes Builder for client code */
actual fun logDebug(tag: String, message: String) {
    println("DBG - $tag : $message")
}

/** MPP method only, use the version that takes Builder for client code */
actual fun logInfo(tag: String, message: String) {
    println("INFO - $tag : $message")
}

/** MPP method only, use the version that takes Builder for client code */
actual fun logWarning(tag: String, message: String, error: Throwable?) {
    println("WRN - $tag : $message")
    if (error != null) {
        println(error)
    }
}

/** MPP method only, use the version that takes Builder for client code */
actual fun logError(tag: String, message: String, error: Throwable?) {
    println("ERR - $tag : $message")
    if (error != null) {
        println(error)
    }
}