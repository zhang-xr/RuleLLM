rule Python_Custom_Install_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that override the install command to execute malicious code."
        confidence = 85
        severity = 75
    strings:
        $class_def = "class CustomInstall"
        $install_override = "def run(self):"
        $cmdclass = "cmdclass={'install':"
    condition:
        all of ($class_def, $install_override, $cmdclass) and
        filesize < 10KB
}