/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop

import org.gradle.api.*
import org.gradle.internal.os.*
import java.io.*

internal fun File.recreateDirectories(): File {
    deleteRecursively()
    mkdirs()
    return this
}

internal fun Task.onlyIfMacos() {
    onlyIf { OperatingSystem.current().isMacOsX }
}
