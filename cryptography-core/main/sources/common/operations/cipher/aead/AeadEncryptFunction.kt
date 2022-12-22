package dev.whyoleg.cryptography.operations.cipher.aead

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.cipher.*

public interface AeadEncryptFunction : EncryptFunction {
    //TODO: naming?
    public fun putAssociatedData(associatedData: Buffer)
}
