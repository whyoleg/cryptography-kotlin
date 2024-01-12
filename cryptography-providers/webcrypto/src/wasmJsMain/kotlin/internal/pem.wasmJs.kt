/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import org.khronos.webgl.*

//language=JavaScript
internal actual fun encodeBase64(array: ByteArray): String = jsEncodeBase64(array.toInt8Array())

private fun jsEncodeBase64(array: Int8Array): String {
    js(
        code = """
    
        var isNodeJs = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
        if (isNodeJs) {
            return Buffer.from(array).toString('base64');
        } else {
            return btoa(String.fromCharCode.apply(null, new Uint8Array(array)));
        }
    
               """
    )
}

//language=JavaScript
internal actual fun decodeBase64(string: String): ByteArray {
    return jsDecodeBase64(string).toByteArray()
}

private fun jsDecodeBase64(string: String): Int8Array {
    js(
        code = """
    
        var isNodeJs = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
        if (isNodeJs) {
            return Buffer.from(string, 'base64');
        } else {
            var binaryString = atob(string);
            var bytes = new Uint8Array(binaryString.length);
            for (var i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return new Int8Array(bytes.buffer);
        }
    
               """
    )
}
