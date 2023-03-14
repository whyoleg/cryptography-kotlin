/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.test.utils

actual val currentPlatform: String by lazy {
    val isNodeJs =
        js("typeof process !== 'undefined' && process.versions != null && process.versions.node != null").unsafeCast<Boolean>()
    when {
        isNodeJs -> {
            val version = js("process.version").unsafeCast<String>()
            val os = js("process.platform").unsafeCast<String>()
            val arch = js("process.arch").unsafeCast<String>()
            "JS(Node) [version=$version, os=$os, arch=$arch]"
        }
        else     -> {
            val userAgent = js("navigator.userAgent").unsafeCast<String>()
            "JS(Browser) [userAgent=$userAgent]"
        }
    }
}
