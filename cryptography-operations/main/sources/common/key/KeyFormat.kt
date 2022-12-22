package dev.whyoleg.cryptography.operations.key

public interface KeyFormat {
    public interface RAW : KeyFormat
    public interface PEM : KeyFormat
    public interface DER : KeyFormat
    public interface JWK : KeyFormat
}
