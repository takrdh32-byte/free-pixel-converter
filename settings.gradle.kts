pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

// यहाँ हम बिना किसी फाइल के सीधे कोड से AndroidX चालू कर रहे हैं
gradle.settingsEvaluated {
    val startParameter = gradle.startParameter
    startParameter.projectProperties = startParameter.projectProperties + mapOf(
        "android.useAndroidX" to "true",
        "android.enableJetifier" to "true"
    )
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "free-pixel-converter"
include(":app")
