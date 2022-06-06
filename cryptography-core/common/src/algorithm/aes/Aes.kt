package dev.whyoleg.cryptography.algorithm.aes

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.operation.*
import dev.whyoleg.vio.*

//encryption AES GCM: (CTR - no tag size and auth tag)
// - constructor: provide IV size, Tag size, key
// - init: generated IV
// - update: put data | get data
// - final: generated auth tag

//decryption:
// - constructor: provide IV size, Tag size, Key
// - init: provide IV
// - update: put data | get data
// - final: provide auth tag
//

public interface Aes : CryptographyAlgorithm {
    public val generate: KeyGenerate<KeySize, AesKey>
    public val import: KeyImport<Unit, AesKey>
}

//TODO: add defaults
//TODO: key wrap/unwrap; KW mode
//TODO: naming of modes
public interface AesKey : SecretKey {
    public val export: KeyExport<Unit>
    public fun ctr(): AesCtrPrimitive
    public fun gcm(
        padding: Boolean,
        tagLength: BinarySize
    ): AesGcmPrimitive

    public fun cbc(padding: Boolean): AesCbcPrimitive
}

//cipher + cmac // + wrap + unwrap
public interface AesCtrPrimitive {
    public val encrypt: CipherOperation<Unit>
    public val decrypt: CipherOperation<Unit>
}

public interface AesCbcPrimitive {
    public val encrypt: CipherOperation<Unit>
    public val decrypt: CipherOperation<Unit>
    public val cmac: MacOperation<Unit>
}

//cipher + gmac // + wrap + unwrap
public interface AesGcmPrimitive {
    public val encrypt: CipherOperation<AssociatedData>
    public val decrypt: CipherOperation<AssociatedData>
    public val gmac: MacOperation<Unit> //TODO: input parameters
}

public class AssociatedData(
    public val bufferView: BufferView
)

private suspend fun test(aes: Aes) {
    aes.generate(KeySize(10.bytes)).gcm(padding = true).encrypt.async(AssociatedData(ByteArray(0).view())) {
        transform(ByteArray(12).view())
    }
}
