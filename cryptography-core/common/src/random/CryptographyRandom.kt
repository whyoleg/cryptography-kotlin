package dev.whyoleg.cryptography.random

import dev.whyoleg.cryptography.*

//TODO: correct interface
public interface CryptographyRandom {
    public fun nextBytes(buffer: BufferView)
}
