package dev.whyoleg.cryptography.hm.algorithm.aes

import dev.whyoleg.cryptography.hm.*
import dev.whyoleg.cryptography.hm.cipher.*
import dev.whyoleg.cryptography.hm.mac.*
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
    public fun generateKey(keySize: BinarySize): AesKey
    public fun importKey(key: BufferView): AesKey //TODO: other imports
}

//TODO: add defaults
//TODO: key wrap/unwrap; KW mode
//TODO: naming of modes
public interface AesKey {
    public fun ctr(): AesCtrPrimitive
    public fun gcm(
        padding: Boolean,
        tagLength: BinarySize
    ): AesGcmPrimitive

    public fun cbc(padding: Boolean): AesCbcPrimitive

    public fun export(output: BufferView)
    public fun export(): BufferView

}

public interface AesCbcPrimitive {
    public val encrypt: CipherPrimitive<Unit>
    public val decrypt: CipherPrimitive<Unit>
    public val cmac: MacPrimitive<Unit>
}

//cipher + cmac // + wrap + unwrap
public interface AesCtrPrimitive {
    public val encrypt: CipherPrimitive<Unit>
    public val decrypt: CipherPrimitive<Unit>
}

//cipher + gmac // + wrap + unwrap
public interface AesGcmPrimitive {
    public val encrypt: CipherPrimitive<AssociatedData>
    public val decrypt: CipherPrimitive<AssociatedData>
    public val mac: MacPrimitive<Unit> //TODO: input parameters
}

public class AssociatedData(
    public val bufferView: BufferView
)

private suspend fun test(aes: Aes) {
    aes.generateKey(10.bytes).gcm(padding = true).encrypt.async(AssociatedData(ByteArray(0).view())) {
        transform(ByteArray(12).view())
    }
}