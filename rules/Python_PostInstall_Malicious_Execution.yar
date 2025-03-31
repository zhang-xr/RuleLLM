rule Python_PostInstall_Malicious_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious post-installation code execution in Python packages"
        confidence = 85
        severity = 90

    strings:
        $post_install = "class PostInstallCommand(install)"
        $run_method = "def run(self)"
        $install_run = "install.run(self)"
        $cmdclass = "'install': PostInstallCommand"

    condition:
        all of ($post_install, $run_method, $install_run, $cmdclass)
}