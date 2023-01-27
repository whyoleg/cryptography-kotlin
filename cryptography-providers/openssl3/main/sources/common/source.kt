package dev.whyoleg.cryptography.openssl3

import dev.whyoleg.cryptography.openssl3.internal.cinterop.*

public fun init(): String {
    OPENSSL_init()
    return OPENSSL_VERSION_TEXT
}
