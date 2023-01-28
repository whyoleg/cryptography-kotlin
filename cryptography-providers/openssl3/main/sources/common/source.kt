package dev.whyoleg.cryptography.openssl3

import dev.whyoleg.cryptography.openssl3.internal.libcrypto.*

public fun init(): String {
    OPENSSL_init()
    return OPENSSL_VERSION_STR
}
