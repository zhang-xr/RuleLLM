rule Python_Custom_Install_Command {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files that override the install command to execute custom code"
        confidence = 80
        severity = 70
    strings:
        $install_class = "class CustomInstall(install):"
        $run_method = "def run(self):"
    condition:
        $install_class and $run_method
}