package dev.whyoleg.cryptography.key

import dev.whyoleg.vio.*

public sealed interface KeyFormat {
    public object RAW : BinaryKeyFormat, SymmetricKeyFormat
    public object DER : BinaryKeyFormat, AsymmetricKeyFormat
    public object PEM : BinaryKeyFormat, AsymmetricKeyFormat
    public object PKCS12 : BinaryKeyFormat, KeyPairFormat
    public object JWK : BinaryKeyFormat, SymmetricKeyFormat, AsymmetricKeyFormat, KeyPairFormat
    public object KeyChain : SymmetricKeyFormat, AsymmetricKeyFormat, KeyPairFormat
}

public sealed interface BinaryKeyFormat : KeyFormat
public sealed interface SymmetricKeyFormat : KeyFormat
public sealed interface AsymmetricKeyFormat : KeyFormat
public sealed interface PublicKeyFormat : AsymmetricKeyFormat
public sealed interface PrivateKeyFormat : AsymmetricKeyFormat
public sealed interface KeyPairFormat : KeyFormat

//file, memory, keychain? + format
public sealed interface KeyData<Format : KeyFormat>
public class MemoryKeyData<Format : BinaryKeyFormat>(public val buffer: BufferView) : KeyData<Format>
public class FileKeyData<Format : BinaryKeyFormat>(public val path: PathView) : KeyData<Format>
public object KeyChainData : KeyData<KeyFormat.KeyChain> //TODO
