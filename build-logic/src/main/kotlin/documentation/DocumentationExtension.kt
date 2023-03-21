/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package documentation

import org.gradle.api.provider.*

abstract class DocumentationExtension {
    abstract val moduleName: Property<String>
    abstract val includes: Property<String>
}
