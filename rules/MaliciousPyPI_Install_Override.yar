rule MaliciousPyPI_Install_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python package install override with suspicious class inheritance"
        confidence = 90
        severity = 85
    strings:
        $class_def = "class CustomInstall(install):"
        $run_method = "def run(self):"
        $install_override = "cmdclass={'install': CustomInstall}"
    condition:
        all of them
}