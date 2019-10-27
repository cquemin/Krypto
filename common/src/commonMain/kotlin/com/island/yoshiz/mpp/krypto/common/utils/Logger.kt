package com.island.yoshiz.mpp.krypto.common.utils

import com.island.yoshiz.mpp.krypto.common.utils.Logger.LEVEL_DEBUG
import com.island.yoshiz.mpp.krypto.common.utils.Logger.LEVEL_ERROR
import com.island.yoshiz.mpp.krypto.common.utils.Logger.LEVEL_INFO
import com.island.yoshiz.mpp.krypto.common.utils.Logger.LEVEL_VERBOSE
import com.island.yoshiz.mpp.krypto.common.utils.Logger.LEVEL_WARN

/**
 * Min loggerLevel to log at. If a log request for a lower loggerLevel is received, it is ignored
 */
var loggerLevel = LEVEL_ERROR + 1

object Logger {
    const val LEVEL_VERBOSE = 1
    const val LEVEL_DEBUG = 2
    const val LEVEL_INFO = 3
    const val LEVEL_WARN = 4
    const val LEVEL_ERROR = 5
}

fun logVerbose(tag: String, buildMessage: MessageBuilder) {
    if (loggerLevel <= LEVEL_VERBOSE) {
        logVerbose(tag, buildMessage())
    }
}

fun logDebug(tag: String, buildMessage: MessageBuilder) {
    if (loggerLevel <= LEVEL_DEBUG) {
        logDebug(tag, buildMessage())
    }
}

fun logInfo(tag: String, buildMessage: MessageBuilder) {
    if (loggerLevel <= LEVEL_INFO) {
        logInfo(tag, buildMessage())
    }
}

fun logWarning(tag: String, buildMessage: MessageBuilder) {
    if (loggerLevel <= LEVEL_WARN) {
        logWarning(tag, buildMessage())
    }
}

fun logWarning(tag: String, error: Throwable?, buildMessage: MessageBuilder) {
    if (loggerLevel <= LEVEL_WARN) {
        logWarning(tag, buildMessage(), error)
    }
}

fun logError(tag: String, buildMessage: MessageBuilder) {
    if (loggerLevel <= LEVEL_ERROR) {
        logError(tag, buildMessage())
    }
}

fun logError(tag: String, error: Throwable?, buildMessage: MessageBuilder) {
    if (loggerLevel <= LEVEL_ERROR) {
        logError(tag, buildMessage(), error)
    }
}

/** MPP method only, use the version that takes Builder for client code */
expect fun logVerbose(tag: String, message: String)

/** MPP method only, use the version that takes Builder for client code */
expect fun logDebug(tag: String, message: String)

/** MPP method only, use the version that takes Builder for client code */
expect fun logInfo(tag: String, message: String)

/** MPP method only, use the version that takes Builder for client code */
expect fun logWarning(tag: String, message: String, error: Throwable? = null)

/** MPP method only, use the version that takes Builder for client code */
expect fun logError(tag: String, message: String, error: Throwable? = null)

typealias MessageBuilder = () -> String