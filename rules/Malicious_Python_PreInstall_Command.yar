rule Malicious_Python_PreInstall_Command {
    meta:
        author = "RuleLLM"
        description = "Detects Python code with a custom installation command that could execute malicious code."
        confidence = 85
        severity = 80
    strings:
        $pre_install_class = "class PreInstallCommand(install):"
        $subprocess_call = "subprocess.check_call"
    condition:
        all of them
}