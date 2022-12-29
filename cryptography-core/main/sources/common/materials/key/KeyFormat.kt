package dev.whyoleg.cryptography.materials.key

public interface KeyFormat {
    public interface RAW : KeyFormat
    public interface PEM : KeyFormat
    public interface DER : KeyFormat
    public interface JWK : KeyFormat
}
