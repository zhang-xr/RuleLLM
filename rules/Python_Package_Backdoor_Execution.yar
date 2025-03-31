rule Python_Package_Backdoor_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious code execution during Python package installation"
        confidence = "95"
        severity = "100"
    strings:
        $install_class = "class CustomInstallCommand"
        $run_method = "def run(self):"
        $compiled_exec = "eval(compile("
        $install_override = "install.run(self)"
    condition:
        all of them
}