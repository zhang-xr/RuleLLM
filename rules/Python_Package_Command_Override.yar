rule Python_Package_Command_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python package setup code that overrides 'develop' or 'install' commands for malicious execution"
        confidence = 85
        severity = 75

    strings:
        $develop_class = /class\s+PostDevelopCommand\(develop\):/
        $install_class = /class\s+PostInstallCommand\(install\):/
        $cmdclass_dict = /cmdclass\s*=\s*\{.*['"]develop['"]\s*:\s*PostDevelopCommand.*['"]install['"]\s*:\s*PostInstallCommand.*\}/

    condition:
        all of ($develop_class, $install_class, $cmdclass_dict)
}