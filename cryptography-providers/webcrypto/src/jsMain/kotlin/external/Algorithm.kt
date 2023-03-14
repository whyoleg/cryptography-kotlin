/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.webcrypto.external

internal sealed external interface Algorithm {
    var name: String
}

internal inline fun <T : Algorithm> Algorithm(name: String, block: T.() -> Unit = {}): T =
    js("{}").unsafeCast<T>().apply {
        this.name = name
        block()
    }

