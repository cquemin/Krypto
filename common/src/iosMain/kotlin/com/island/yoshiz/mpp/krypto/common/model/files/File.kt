package com.island.yoshiz.mpp.krypto.common.model.files

import com.island.yoshiz.mpp.krypto.common.utils.logWarning
import kotlinx.cinterop.ObjCObjectVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.Foundation.NSError
import platform.Foundation.NSFileManager
import platform.Foundation.NSURL

actual class File actual constructor(private val path: String) {
    private val fileManager = NSFileManager.defaultManager

    actual fun exists(): Boolean {
        return fileManager.fileExistsAtPath(path)
    }

    actual fun delete(): Boolean = memScoped {
        val error = alloc<ObjCObjectVar<NSError?>>()

        val deleted = fileManager.removeItemAtPath(path, error.ptr)
        if (!deleted) {
            logWarning(
                    "File", "Unable to remove $path\n" +
                    "${error.value?.localizedDescription}"
            )
        }
        return@memScoped deleted
    }

    actual fun renameTo(dest: File): Boolean = memScoped {
        val error = alloc<ObjCObjectVar<NSError?>>()

        val source = NSURL(fileURLWithPath = path)
        val destination = NSURL(fileURLWithPath = dest.getAbsolutePath())

        val moved = fileManager.moveItemAtURL(source, destination, error.ptr)
        if (!moved) {
            logWarning(
                    "File", "Unable to move the file $path to ${dest.getAbsolutePath()}\n" +
                    "${error.value?.localizedDescription}"
            )
        }

        return@memScoped moved
    }

    actual fun getAbsolutePath(): String {
        return path
    }
}