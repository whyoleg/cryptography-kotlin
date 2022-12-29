package dev.whyoleg.cryptography.operations.signature

import dev.whyoleg.cryptography.io.*

public interface SignatureGenerator {
    public val signatureSize: Int
    public suspend fun generateSignature(dataInput: Buffer): Buffer
    public suspend fun generateSignature(dataInput: Buffer, signatureOutput: Buffer): Buffer
    public fun generateSignatureBlocking(dataInput: Buffer): Buffer
    public fun generateSignatureBlocking(dataInput: Buffer, signatureOutput: Buffer): Buffer
}
