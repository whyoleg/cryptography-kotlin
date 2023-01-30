package dev.whyoleg.cryptography.openssl3

import dev.whyoleg.cryptography.openssl3.internal.libcrypto.*
import kotlinx.cinterop.*

public fun init(): String? {
    OPENSSL_init()

    return OpenSSL_version(OPENSSL_VERSION_STRING)?.toKString().also {
        println(it)
    }
}

public fun major(): Int = OPENSSL_version_major().convert()

