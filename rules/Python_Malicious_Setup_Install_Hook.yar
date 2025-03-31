rule Python_Malicious_Setup_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects malicious install hooks in Python setup scripts"
        confidence = 95
        severity = 85
    strings:
        $cmdclass = "cmdclass={'install': PostInstallCommand}"
        $install_override = "def run(self):"
        $install_chain = "install.run(self)"
        $custom_action = /[\w]+\(\)/
    condition:
        all of ($cmdclass, $install_override, $install_chain) and 1 of ($custom_action)
}