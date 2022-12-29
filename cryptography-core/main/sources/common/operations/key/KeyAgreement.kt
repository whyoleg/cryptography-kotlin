package dev.whyoleg.cryptography.operations.key

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*

//TODO: decide on name - agree on shared secret key not just a key
public interface KeyAgreement<KF : KeyFormat> {
    //TODO: decide on name
    // add length parameter?
    public suspend fun computeSharedSecretWith(keyFormat: KF, keyInput: Buffer): Buffer
    public suspend fun computeSharedSecretWith(keyFormat: KF, keyInput: Buffer, sharedSecretOutput: Buffer): Buffer
    public fun computeSharedSecretWithBlocking(keyFormat: KF, keyInput: Buffer): Buffer
    public fun computeSharedSecretWithBlocking(keyFormat: KF, keyInput: Buffer, sharedSecretOutput: Buffer): Buffer
}
