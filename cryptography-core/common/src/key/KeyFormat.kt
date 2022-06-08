package dev.whyoleg.cryptography.key

public sealed interface KeyFormat {
    public object RAW : SecretKeyFormat
    public object DER : PublicKeyFormat, PrivateKeyFormat
    public object PEM : PublicKeyFormat, PrivateKeyFormat
    public object PKCS12 : KeyPairFormat
    public object JWK : PublicKeyFormat, PrivateKeyFormat, KeyPairFormat, SecretKeyFormat
}

public sealed interface KeyPairFormat : KeyFormat
public sealed interface PrivateKeyFormat : KeyFormat
public sealed interface PublicKeyFormat : KeyFormat
public sealed interface SecretKeyFormat : KeyFormat
