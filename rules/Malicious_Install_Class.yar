rule Malicious_Install_Class {
    meta:
        author = "RuleLLM"
        description = "Detects malicious install class overriding in Python packages"
        confidence = 90
        severity = 85
    strings:
        $install_override = "cmdclass={'install':"
        $custom_class = "class CustomInstall(install)"
        $run_method = "def run(self):"
        $install_run = "install.run(self)"
    condition:
        all of them and
        filesize < 10KB
}