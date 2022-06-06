package dev.whyoleg.cryptography.impl

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*
import dev.whyoleg.vio.*

public class Hmac(
    public val hash: CryptographyPrimitiveParameters<HashPrimitive>
) : CryptographyPrimitiveParameters<HmacPrimitive>

public interface HmacKey : MacSecretKey {
    public val export: KeyExportOperation<Unit, Unit>
}

public interface HmacPrimitive : CryptographyPrimitive {
    public val import: KeyImportOperation<Unit, HmacKey>
    public val generate: KeyGenerateOperation<Unit, HmacKey>
}

private fun test(registry: CryptographyPrimitiveProvider) {
    val primitive = registry.get(Hmac(Sha.SHA256))
    val key = primitive.generate(Unit, Unit)
    val signature = key.sign(ByteArray(0).view())
    val verified = key.verify(signature)
}
