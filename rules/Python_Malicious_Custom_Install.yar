rule Python_Malicious_Custom_Install {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages using custom install classes"
        confidence = 95
        severity = 85
    strings:
        $class_def = "class CustomInstall(install)"
        $run_method = "def run(self):"
        $install_run = "install.run(self)"
    condition:
        all of them and filesize < 10KB
}