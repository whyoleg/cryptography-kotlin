package dev.whyoleg.cryptography.operations.derive

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*

//TODO: think about name a little more...
//key agreement
public interface SharedSecretDerivative<KF : KeyFormat> {
    public suspend fun deriveSharedSecretFrom(keyFormat: KF, keyInput: Buffer): Buffer
    public suspend fun deriveSharedSecretFrom(keyFormat: KF, keyInput: Buffer, sharedSecretOutput: Buffer): Buffer
    public fun deriveSharedSecretFromBlocking(keyFormat: KF, keyInput: Buffer): Buffer
    public fun deriveSharedSecretFromBlocking(keyFormat: KF, keyInput: Buffer, sharedSecretOutput: Buffer): Buffer
}
