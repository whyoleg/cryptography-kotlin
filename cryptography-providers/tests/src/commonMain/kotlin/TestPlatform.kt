/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import kotlinx.serialization.*

internal expect val currentTestPlatform: TestPlatform

@Serializable
sealed class TestPlatform {
    @Serializable
    sealed class JVM : TestPlatform()

    @SerialName("jdk")
    @Serializable
    data class JDK(
        val major: Int,
        val version: String,
        val os: String,
        val arch: String,
    ) : JVM()

    @SerialName("android")
    @Serializable
    data class Android(
        val apiLevel: Int,
    ) : JVM()

    @SerialName("native")
    @Serializable
    data class Native(
        val os: String,
        val arch: String,
        val debug: Boolean,
    ) : TestPlatform()

    @Serializable
    sealed class JS : TestPlatform() {
        @SerialName("js.browser")
        @Serializable
        data class Browser(
            val brand: String,
            val platform: String,
            val userAgent: String,
        ) : JS()

        @SerialName("js.nodejs")
        @Serializable
        data class NodeJS(
            val version: String,
            val os: String,
            val arch: String,
        ) : JS()
    }

    @Serializable
    sealed class Wasm : TestPlatform()

    @SerialName("wasm.wasi")
    @Serializable
    data object WasmWasi : Wasm()

    @Serializable
    sealed class WasmJs : Wasm() {
        @SerialName("wasm.js.browser")
        @Serializable
        data class Browser(
            val brand: String,
            val platform: String,
            val userAgent: String,
        ) : JS()

        @SerialName("wasm.js.nodejs")
        @Serializable
        data class NodeJS(
            val version: String,
            val os: String,
            val arch: String,
        ) : JS()
    }
}

val TestPlatform.isBrowser: Boolean get() = this is TestPlatform.JS.Browser || this is TestPlatform.WasmJs.Browser
val TestPlatform.isAndroid: Boolean get() = this is TestPlatform.Android
inline fun TestPlatform.isAndroid(block: TestPlatform.Android.() -> Boolean): Boolean = this is TestPlatform.Android && block(this)

val TestPlatform.isJdk: Boolean get() = this is TestPlatform.JDK
inline fun TestPlatform.isJdk(block: TestPlatform.JDK.() -> Boolean): Boolean = this is TestPlatform.JDK && block(this)
