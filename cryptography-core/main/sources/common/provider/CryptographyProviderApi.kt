package dev.whyoleg.cryptography.provider

//TODO: rename to CryptographyProviderApi
@RequiresOptIn(
    message = "API of everything what is implemented in providers is experimental for now and subject to change " +
            "(if possible in backward-compatible way)",
    level = RequiresOptIn.Level.ERROR
)
public annotation class CryptographyProviderApi
