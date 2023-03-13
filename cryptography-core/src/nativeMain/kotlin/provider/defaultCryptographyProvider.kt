package dev.whyoleg.cryptography.provider

private val providers = mutableListOf<Lazy<CryptographyProvider>>()

@PublishedApi
internal fun registerProvider(block: () -> CryptographyProvider): Unit = registerProvider(lazy(block))

@PublishedApi
internal fun registerProvider(lazy: Lazy<CryptographyProvider>) {
    providers += lazy
}

internal actual fun defaultCryptographyProvider(): CryptographyProvider = providers.first().value
