plugins {
    base
}

group = "org.openproof"
version = "1.1.0-rc1"

val gradleLib = requireNotNull(gradle.gradleHomeDir) {
    "The Gradle home directory is required to compile the Kotlin SDK"
}.resolve("lib")
val embeddedStdlib = gradleLib.listFiles()
    ?.singleOrNull { it.name.startsWith("kotlin-stdlib-") && it.extension == "jar" }
    ?: error("The pinned Gradle distribution does not contain exactly one Kotlin stdlib")
val sdkSource = layout.projectDirectory.file(
    "src/main/kotlin/org/openproof/identity/OpenProof.kt")
val sdkJar = layout.buildDirectory.file("libs/openproof-identity-$version.jar")
val sdkTestSource = layout.projectDirectory.file(
    "src/test/kotlin/org/openproof/identity/SdkSmoke.kt")
val sdkTestJar = layout.buildDirectory.file("test/openproof-identity-smoke.jar")

val compileKotlinSdk by tasks.registering(JavaExec::class) {
    group = "build"
    description = "Compiles the dependency-free OpenProof Kotlin SDK with Gradle's pinned compiler."
    classpath = fileTree(gradleLib) { include("*.jar") }
    mainClass.set("org.jetbrains.kotlin.cli.jvm.K2JVMCompiler")
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    inputs.file(sdkSource)
    outputs.file(sdkJar)
    doFirst {
        sdkJar.get().asFile.parentFile.mkdirs()
        args(
            "-no-stdlib", "-no-reflect",
            "-classpath", embeddedStdlib.absolutePath,
            sdkSource.asFile.absolutePath,
            "-d", sdkJar.get().asFile.absolutePath
        )
    }
}

val compileKotlinSdkTest by tasks.registering(JavaExec::class) {
    group = "verification"
    classpath = fileTree(gradleLib) { include("*.jar") }
    mainClass.set("org.jetbrains.kotlin.cli.jvm.K2JVMCompiler")
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    inputs.files(sdkSource, sdkTestSource)
    outputs.file(sdkTestJar)
    doFirst {
        sdkTestJar.get().asFile.parentFile.mkdirs()
        args(
            "-no-stdlib", "-no-reflect",
            "-classpath", embeddedStdlib.absolutePath,
            sdkSource.asFile.absolutePath,
            sdkTestSource.asFile.absolutePath,
            "-d", sdkTestJar.get().asFile.absolutePath
        )
    }
}

val testKotlinSdk by tasks.registering(JavaExec::class) {
    group = "verification"
    dependsOn(compileKotlinSdkTest)
    classpath = files(sdkTestJar, embeddedStdlib)
    mainClass.set("org.openproof.identity.SdkSmokeKt")
}

tasks.assemble {
    dependsOn(compileKotlinSdk)
}

tasks.check {
    dependsOn(compileKotlinSdk, testKotlinSdk)
}
