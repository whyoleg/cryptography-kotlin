/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

internal actual val currentTestPlatform: TestPlatform = when {
    System.getProperty("java.vendor")!!.contains("android", ignoreCase = true) -> {
        TestPlatform.Android(
            apiLevel = Class.forName($$"android.os.Build$VERSION").getField("SDK_INT").get(null) as Int
        )
    }
    else                                                                       -> {
        val version = System.getProperty("java.version") ?: ""
        TestPlatform.JDK(
            major = when (val major = version.substringBefore(".").toIntOrNull() ?: -1) {
                1    -> 8
                else -> major
            },
            version = version,
            os = System.getProperty("os.name") ?: "",
            arch = System.getProperty("os.arch") ?: ""
        )
    }
}
