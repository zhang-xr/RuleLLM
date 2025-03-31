rule Malicious_Custom_Install_Class {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages with custom install classes"
        confidence = 85
        severity = 75

    strings:
        // Custom install class pattern
        $custom_install = "class CustomInstall(install)"
        $cmdclass = "cmdclass={'install': CustomInstall}"

    condition:
        // Match if both patterns are present
        all of them
}