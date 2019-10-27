@file:JvmName("LoggerJvm")

package com.island.yoshiz.mpp.krypto.common.utils

import java.io.PrintStream

actual fun logVerbose(tag: String, message: String) {
    logIntoJvmNormalOutput(tag, message)
}

actual fun logDebug(tag: String, message: String) {
    logIntoJvmNormalOutput(tag, message)
}

actual fun logInfo(tag: String, message: String) {
    logIntoJvmNormalOutput(tag, message)
}

actual fun logWarning(tag: String, message: String, error: Throwable?) {
    logIntoJvmErrorOutput(tag, message, error)
}

actual fun logError(tag: String, message: String, error: Throwable?) {
    logIntoJvmErrorOutput(tag, message, error)
}

// Validated true on OpenJDK and Oracle JDK, false on Android 7
private val isRunningInJvm =
        System.getProperty("java.runtime.name")?.toLowerCase()?.contains(Regex("jdk|java.* se"))
                ?: false

private fun logIntoJvmNormalOutput(tag: String, message: String, error: Throwable? = null) {
    logForJvm(System.out, tag, message, error)
}

private fun logIntoJvmErrorOutput(tag: String, message: String, error: Throwable? = null) {
    logForJvm(System.err, tag, message, error)
}

private fun logForJvm(printStream: PrintStream, tag: String, message: String, error: Throwable?) {
    printStream.println("$tag\t$message")
    error?.printStackTrace()
}
