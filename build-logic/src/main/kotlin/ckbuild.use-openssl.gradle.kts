/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.openssl.*

val configuration = configurations.create("openssl3Dependency")

dependencies {
    configuration("ckbuild.dependencies.openssl:openssl3-all:3.0.8-build-2@zip")
}

val archiveOperations = objects.newInstance<Injected>().archiveOperations
val setupOpenssl3 by tasks.registering(Sync::class) {
    from(provider { archiveOperations.zipTree(configuration.singleFile) })
    into(temporaryDir)
    includeEmptyDirs = false
}

internal abstract class Injected @Inject constructor(
    val archiveOperations: ArchiveOperations,
)

extensions.create<Openssl3Extension>(
    "openssl3",
    layout.dir(setupOpenssl3.map { it.destinationDir })
)
