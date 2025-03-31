rule Suspicious_Python_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects custom install command hooks in Python setup scripts"
        confidence = 85
        severity = 75
    strings:
        $install_class = "class CustomInstallCommand"
        $install_method = "def run(self):"
        $setup_call = "install.run(self)"
        $external_call = "requests.get"
    condition:
        all of ($install_class, $install_method, $setup_call) and
        any of ($external_call)
}