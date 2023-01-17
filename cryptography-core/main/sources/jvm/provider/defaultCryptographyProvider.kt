package dev.whyoleg.cryptography.provider

import java.util.*

@Deprecated("", level = DeprecationLevel.ERROR)
public interface CryptographyProviderContainer {
    public val provider: Lazy<CryptographyProvider>
}

@Suppress("DEPRECATION_ERROR")
internal actual fun defaultCryptographyProvider(): CryptographyProvider {
    val cls = CryptographyProviderContainer::class.java
    return ServiceLoader.load(cls, cls.classLoader).first().provider.value
}
