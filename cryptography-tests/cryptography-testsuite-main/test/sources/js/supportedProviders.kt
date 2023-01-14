package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.webcrypto.*

internal actual val supportedProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.WebCrypto
)
internal actual val currentPlatform: String by lazy {
    val isNodeJs =
        js("typeof process !== 'undefined' && process.versions != null && process.versions.node != null").unsafeCast<Boolean>()
    when {
        isNodeJs -> "NodeJS"
        else     -> "Browser"
    }
}
