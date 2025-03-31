rule Python_Malicious_Install_Class {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python install classes in setup files"
        confidence = 95
        severity = 85
    strings:
        $install_class = "class gpl(install)"
        $malicious_run = "def run(self):"
        $cmdclass = "cmdclass = {\"install\": gpl}"
    condition:
        all of them
}