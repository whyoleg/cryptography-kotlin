package dev.whyoleg.cryptography.random

import kotlin.random.*

//TODO: decide on reseed methods
public abstract class SecureRandom : Random() {
    public abstract fun reseed(): SecureRandom //TODO!!!
}
