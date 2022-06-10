package dev.whyoleg.cryptography.key

public sealed interface KeyFormat {
    public object RAW : SymmetricKeyFormat
    public object DER : AsymmetricKeyFormat
    public object PEM : AsymmetricKeyFormat
    public object PKCS12 : KeyPairFormat
    public object JWK : SymmetricKeyFormat, AsymmetricKeyFormat, KeyPairFormat
}

public sealed interface SymmetricKeyFormat : KeyFormat
public sealed interface AsymmetricKeyFormat : KeyFormat
public sealed interface PublicKeyFormat : AsymmetricKeyFormat
public sealed interface PrivateKeyFormat : AsymmetricKeyFormat
public sealed interface KeyPairFormat : KeyFormat
