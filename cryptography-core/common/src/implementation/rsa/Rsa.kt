package dev.whyoleg.cryptography.implementation.rsa

import dev.whyoleg.cryptography.algorithm.*
import dev.whyoleg.cryptography.function.*
import dev.whyoleg.cryptography.primitive.*

public interface Rsa<Pub : Rsa.PublicKey<*, *>, Pri : Rsa.PrivateKey<*, *>, KP : Rsa.KeyPair<Pub, Pri>> :
    CryptographyPrimitiveGenerator<Unit, KP>,
    CryptographyPrimitiveImporter<Unit, KP> {

    public val publicKey: CryptographyPrimitiveImporter<Unit, Pub>
    public val privateKey: CryptographyPrimitiveImporter<Unit, Pri>

    //add verify
    public interface PublicKey<IP, EF : EncryptFunction> :
        ExportablePrimitive<Unit, Unit>,
        EncryptPrimitive<IP, EF>

    //add sign
    public interface PrivateKey<IP, DF : DecryptFunction> :
        ExportablePrimitive<Unit, Unit>,
        DecryptPrimitive<IP, DF>

    public interface KeyPair<Pub : PublicKey<*, *>, Pri : PrivateKey<*, *>> : ExportablePrimitive<Unit, Unit> {
        public val publicKey: Pub
        public val privateKey: Pri
    }

    public companion object {
        public val NoPadding: CryptographyAlgorithm<RsaNoPadding> = CryptographyAlgorithm("RSA")
        public val OAEP: CryptographyAlgorithm<RsaOaep> = CryptographyAlgorithm("RSA-OAEP")
    }

}
