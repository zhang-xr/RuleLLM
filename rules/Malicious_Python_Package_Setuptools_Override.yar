rule Malicious_Python_Package_Setuptools_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python package that overrides setuptools commands to execute malicious code"
        confidence = 85
        severity = 80

    strings:
        $develop_override = /class\s+PostDevelopCommand\s*\(\s*develop\s*\):/
        $install_override = /class\s+PostInstallCommand\s*\(\s*install\s*\):/
        $cmdclass = /cmdclass\s*=\s*{.*['"]develop['"]\s*:\s*PostDevelopCommand.*['"]install['"]\s*:\s*PostInstallCommand.*}/

    condition:
        all of them
}