package dev.whyoleg.cryptography.random

import platform.posix.*

internal fun errnoCheck(): Nothing {
    val message = when (val value = errno) {
        EFAULT -> "The address referred to by buf is outside the accessible address space."
        EINTR  -> "The call was interrupted by a signal handler; see the description of how interrupted read(2) calls on 'slow' devices are handled with and without the SA_RESTART flag in the signal(7) man page."
        EINVAL -> "An invalid flag was specified in flags."
        else   -> "POSIX error: $value"
    }
    error(message)
}
