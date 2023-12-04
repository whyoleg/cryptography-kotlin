/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.external

import org.khronos.webgl.*

private val isNodeJs =
    js("typeof process !== 'undefined' && process.versions != null && process.versions.node != null").unsafeCast<Boolean>()

internal val WebCrypto: Crypto by lazy {
    if (isNodeJs) {
        js("eval('require')('node:crypto').webcrypto")
    } else {
        js("(window ? (window.crypto ? window.crypto : window.msCrypto) : self.crypto)")
    }
}

@Suppress("UNUSED_ANONYMOUS_PARAMETER")
internal val encodeBase64: (ArrayBuffer) -> String = if (isNodeJs) {
    { array ->
        js("Buffer.from(array).toString('base64')").unsafeCast<String>()
    }
} else {
    { array ->
        js("btoa(String.fromCharCode.apply(null, new Uint8Array(array)))").unsafeCast<String>()
    }
}

@Suppress("UNUSED_ANONYMOUS_PARAMETER")
internal val decodeBase64: (String) -> ByteArray = if (isNodeJs) {
    { string ->
        js("Buffer.from(string, 'base64')").unsafeCast<ByteArray>()
    }
} else {
    { string ->
        js("atob(string)").unsafeCast<String>().run {
            ByteArray(length) { get(it).code.toByte() }
        }
    }
}
