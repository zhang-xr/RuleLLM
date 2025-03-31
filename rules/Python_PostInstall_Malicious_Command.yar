rule Python_PostInstall_Malicious_Command {
    meta:
        author = "RuleLLM"
        description = "Detects malicious override of the install command in Python setup scripts"
        confidence = 95
        severity = 90

    strings:
        $post_install_class = "class PostInstallCommand(install):"
        $run_method = "def run(self):"
        $install_call = "install.run(self)"

    condition:
        all of ($post_install_class, $run_method, $install_call)
}