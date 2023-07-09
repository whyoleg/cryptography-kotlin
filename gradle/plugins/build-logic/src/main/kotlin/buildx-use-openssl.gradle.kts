/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import openssl.*

rootProject.apply<OpensslRootPlugin>()

extensions.create("openssl", OpensslExtension::class.java, rootProject)
