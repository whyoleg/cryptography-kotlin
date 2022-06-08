package dev.whyoleg.cryptography.key

public interface KeyGenerationParameters<K : Key>

public abstract class SecretKeyGenerationParameters<K : SecretKey>(
    public val keySize: KeySize
) : KeyGenerationParameters<K>

