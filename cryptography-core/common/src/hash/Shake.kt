package dev.whyoleg.cryptography.hash

public sealed class Shake(override val digestSize: DigestSize) : HashParameters {
    public class SHAKE128(digestSize: DigestSize) : Shake(digestSize)
    public class SHAKE256(digestSize: DigestSize) : Shake(digestSize)
}
