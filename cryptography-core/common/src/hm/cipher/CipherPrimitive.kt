package dev.whyoleg.cryptography.hm.cipher

import dev.whyoleg.cryptography.hm.*
import dev.whyoleg.vio.*

public interface CipherPrimitive<P> : CryptographyFunctionFactory<P, CipherFunction> {
    public val async: Async<P>

    public operator fun invoke(input: BufferView, output: BufferView, parameters: P)
    public operator fun invoke(input: BufferView, parameters: P): BufferView

    public interface Async<P> : CryptographyFunctionFactory<P, CipherFunction.Async> {
        public suspend operator fun invoke(input: BufferView, output: BufferView, parameters: P)
        public suspend operator fun invoke(input: BufferView, parameters: P): BufferView
    }
}

public operator fun CipherPrimitive<Unit>.invoke(input: BufferView, output: BufferView) {
    invoke(input, output, Unit)
}

public operator fun CipherPrimitive<Unit>.invoke(input: BufferView): BufferView {
    return invoke(input, Unit)
}

public suspend operator fun CipherPrimitive.Async<Unit>.invoke(input: BufferView, output: BufferView) {
    invoke(input, output, Unit)
}

public suspend operator fun CipherPrimitive.Async<Unit>.invoke(input: BufferView): BufferView {
    return invoke(input, Unit)
}

