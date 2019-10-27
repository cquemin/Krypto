package com.island.yoshiz.mpp.krypto.common.model.files

expect class File(path: String) {

    fun exists(): Boolean

    fun delete(): Boolean

    fun renameTo(dest: File): Boolean

    fun getAbsolutePath(): String
}