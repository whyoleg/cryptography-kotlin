package dev.whyoleg.cryptography.hm.hash

import dev.whyoleg.cryptography.hm.*
import dev.whyoleg.vio.*

public interface HashPrimitive<P> : CryptographyFunctionFactory<P, HashFunction> {
    public val async: Async<P>

    public operator fun invoke(input: BufferView, output: BufferView, parameters: P)
    public operator fun invoke(input: BufferView, parameters: P): BufferView

    public interface Async<P> : CryptographyFunctionFactory<P, HashFunction.Async> {
        public suspend operator fun invoke(input: BufferView, output: BufferView, parameters: P)
        public suspend operator fun invoke(input: BufferView, parameters: P): BufferView
    }
}

public operator fun HashPrimitive<Unit>.invoke(input: BufferView, output: BufferView) {
    invoke(input, output, Unit)
}

public operator fun HashPrimitive<Unit>.invoke(input: BufferView): BufferView {
    return invoke(input, Unit)
}

public suspend operator fun HashPrimitive.Async<Unit>.invoke(input: BufferView, output: BufferView) {
    invoke(input, output, Unit)
}

public suspend operator fun HashPrimitive.Async<Unit>.invoke(input: BufferView): BufferView {
    return invoke(input, Unit)
}
