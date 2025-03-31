rule Python_Package_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that use setup.py to execute malicious code during installation."
        confidence = 85
        severity = 75
    strings:
        $setup = "setup("
        $cmdclass = "cmdclass="
        $install = "install"
        $run_method = "def run("
    condition:
        all of ($setup, $cmdclass, $install, $run_method)
}