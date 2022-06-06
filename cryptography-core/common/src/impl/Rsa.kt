package dev.whyoleg.cryptography.impl

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*

public sealed class Rsa<P : CryptographyPrimitive> : CryptographyPrimitiveParameters<P> {

    public class OAEP(
        public val hash: CryptographyPrimitiveParameters<HashPrimitive>
    ) : Rsa<CryptographyPrimitive>() //cipher primitive

    public class PSS(

    ) : Rsa<CryptographyPrimitive>() //signature primitive
}

//TODO: name
public interface RsaPrimitive : CryptographyPrimitive {
    public val public: RsaPublicPrimitive
}

public interface RsaPublicPrimitive {
    public val import: KeyImportOperation<Unit, RsaPublicKey>
    public val generate: KeyImportOperation<Unit, RsaPublicKey>
}

public interface RsaKey : Key

public interface RsaPublicKey : RsaKey, CipherPublicKey, SignaturePublicKey {
    public val export: KeyExportOperation<Unit, Unit>
}

public interface RsaPrivateKey : RsaKey, CipherPrivateKey, SignaturePrivateKey {
    public val export: KeyExportOperation<Unit, Unit>
}

public interface RsaKeyPair : RsaKey, CipherKeyPair, SignatureKeyPair {
    override val publicKey: RsaPublicKey
    override val privateKey: RsaPrivateKey
}
