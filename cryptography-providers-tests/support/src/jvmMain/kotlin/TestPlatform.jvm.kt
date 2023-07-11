/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.support

internal actual val currentTestPlatform: TestPlatform = run {
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
