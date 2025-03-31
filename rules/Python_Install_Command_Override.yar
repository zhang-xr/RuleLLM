rule Python_Install_Command_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python code overriding install command for malicious purposes"
        confidence = 85
        severity = 85
    strings:
        $postinstall = "class PostInstallCommand(install)"
        $run_method = "def run(self)"
        $install_override = "cmdclass={'install'"
    condition:
        all of them and filesize < 10KB
}