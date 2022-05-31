package dev.whyoleg.cryptography.implementation

import dev.whyoleg.cryptography.*

public class InitializationVector(
    public val bufferView: BufferView
)

public class AssociatedData(
    public val bufferView: BufferView
)

public class AuthTag(
    public val bufferView: BufferView
)
