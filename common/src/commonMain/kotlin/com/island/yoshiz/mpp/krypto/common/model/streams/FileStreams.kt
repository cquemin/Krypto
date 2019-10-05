package com.island.yoshiz.mpp.krypto.common.model.streams

import com.island.yoshiz.mpp.krypto.common.model.files.File

expect class FileInputStream(file: File) : InputStream
expect class FileOutputStream(file: File) : OutputStream