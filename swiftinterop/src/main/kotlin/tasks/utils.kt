/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop.tasks

import java.io.*

internal fun File.recreateDirectories() {
    deleteRecursively()
    mkdirs()
}
