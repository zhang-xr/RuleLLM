rule Suspicious_Setup_Function {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious use of the setup function in Python code"
        confidence = 80
        severity = 85

    strings:
        $setup = "setup"
        $packages = "packages"
        $install_requires = "install_requires"

    condition:
        all of ($setup, $packages, $install_requires) and not filesize < 1KB
}