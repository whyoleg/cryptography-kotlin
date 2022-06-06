package dev.whyoleg.cryptography.impl

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*

public class Gmac(
    //TODO: what parameters, f.e. aes based, or other
) : CryptographyPrimitiveParameters<GmacPrimitive>

//TODO: simple secret key primitive
public interface GmacPrimitive : CryptographyPrimitive {
    public val import: KeyImportOperation<Unit, GmacKey>
    public val generate: KeyGenerateOperation<Unit, GmacKey>
}

//TODO: simple mac key
public interface GmacKey : MacSecretKey {
    public val export: KeyExportOperation<Unit, Unit>
}
