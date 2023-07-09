/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.test

actual val currentPlatform: String by lazy {
    "JVM($currentPlatformJvmVersion) [version=${
        System.getProperty("java.version")
    }, os=${
        System.getProperty("os.name")
    }, arch=${
        System.getProperty("os.arch")
    }]"
}

actual val currentPlatformJvmVersion: Int? by lazy {
    val version = System.getProperty("java.version").substringBefore(".").toIntOrNull() ?: -1
    if (version == 1) 8
    else version
}
