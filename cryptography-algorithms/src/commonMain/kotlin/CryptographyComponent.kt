/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

public interface CryptographyComponent<SELF : CryptographyComponent<SELF>> {
    public fun <I : Any, P : Any> instantiate(
        tag: Tag<SELF, I, P>,
        parameters: P,
    ): I

    // TODO: make it an abstract class with a name?
    public interface Tag<C : CryptographyComponent<C>, I : Any, P : Any>
}

@Suppress("NOTHING_TO_INLINE")
public inline operator fun <C : CryptographyComponent<C>, I : Any, P : Any> CryptographyComponent.Tag<C, I, P>.invoke(
    component: C,
    parameters: P,
): I = component.instantiate(this, parameters)

@Suppress("NOTHING_TO_INLINE")
public inline operator fun <C : CryptographyComponent<C>, I : Any> CryptographyComponent.Tag<C, I, Unit>.invoke(
    component: C,
): I = component.instantiate(this, Unit)
