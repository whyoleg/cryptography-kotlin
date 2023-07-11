/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.support

import kotlinx.serialization.*

internal expect val currentTestPlatform: TestPlatform

@Serializable
sealed class TestPlatform {
    @Serializable
    sealed class JVM : TestPlatform()

    @Serializable
    data class JDK(
        val major: Int,
        val version: String,
        val os: String,
        val arch: String,
    ) : JVM()

    @Serializable
    data class Native(
        val os: String,
        val arch: String,
        val debug: Boolean,
    ) : TestPlatform()

    @Serializable
    sealed class JS : TestPlatform()

    @Serializable
    data class Browser(
        val brand: String,
        val platform: String,
        val userAgent: String,
    ) : JS()

    @Serializable
    data class NodeJS(
        val version: String,
        val os: String,
        val arch: String,
    ) : JS()
}

val TestPlatform.isBrowser: Boolean get() = this is TestPlatform.Browser

val TestPlatform.isJdk: Boolean get() = this is TestPlatform.JDK
inline fun TestPlatform.isJdk(block: TestPlatform.JDK.() -> Boolean): Boolean = this is TestPlatform.JDK && block(this)
