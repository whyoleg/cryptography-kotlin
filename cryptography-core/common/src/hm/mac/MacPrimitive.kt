package dev.whyoleg.cryptography.hm.mac

import dev.whyoleg.cryptography.hm.*
import dev.whyoleg.vio.*

public interface MacPrimitive<P> : CryptographyFunctionFactory<P, MacFunction> {
    public val async: Async<P>

    public operator fun invoke(input: BufferView, output: BufferView, parameters: P)
    public operator fun invoke(input: BufferView, parameters: P): BufferView

    public interface Async<P> : CryptographyFunctionFactory<P, MacFunction.Async> {
        public suspend operator fun invoke(input: BufferView, output: BufferView, parameters: P)
        public suspend operator fun invoke(input: BufferView, parameters: P): BufferView
    }
}

public operator fun MacPrimitive<Unit>.invoke(input: BufferView, output: BufferView) {
    invoke(input, output, Unit)
}

public operator fun MacPrimitive<Unit>.invoke(input: BufferView): BufferView {
    return invoke(input, Unit)
}

public suspend operator fun MacPrimitive.Async<Unit>.invoke(input: BufferView, output: BufferView) {
    invoke(input, output, Unit)
}

public suspend operator fun MacPrimitive.Async<Unit>.invoke(input: BufferView): BufferView {
    return invoke(input, Unit)
}

