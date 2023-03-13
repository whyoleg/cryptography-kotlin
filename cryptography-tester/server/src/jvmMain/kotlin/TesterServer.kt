package dev.whyoleg.cryptography.tester.server

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.callloging.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.routing.*
import java.nio.file.*
import kotlin.io.path.*

fun main(vararg args: String) {
    check(args.size <= 1) { "Expected 1 argument, got ${args.size}" }
    val instanceId = args.firstOrNull() ?: "local"

    @OptIn(ExperimentalPathApi::class)
    val storagePath = Path("cryptography-tester/storage").also(Path::deleteRecursively)
    embeddedServer(Netty, port = 9000) {
        install(CallLogging)
        install(CORS) { anyHost() }
        routing {
            compatibility(instanceId, storagePath.resolve("compatibility"))
        }
    }.start(wait = true)
}
