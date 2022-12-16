package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*

public interface AeadDecryptFunction : DecryptFunction {
    //TODO: naming?
    public fun putAssociatedData(associatedData: Buffer)
}
