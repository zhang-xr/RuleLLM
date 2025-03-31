rule Malicious_Python_PostInstall_Command {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that override the install command to execute malicious code"
        confidence = 85
        severity = 75

    strings:
        $cmdclass = "cmdclass"
        $post_install = "PostInstallCommand"
        $install_run = "install.run(self)"
        $custom_command = "def run(self):"

    condition:
        all of ($cmdclass, $post_install) and 2 of ($install_run, $custom_command)
}