rule Python_Malicious_PostInstall {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package installation behavior using a custom PostInstallCommand."
        confidence = 85
        severity = 90

    strings:
        $post_install_class = "class PostInstallCommand(install):"
        $run_method = "def run(self):"
        $setup_call = "setup("
        $cmdclass = "cmdclass={"

    condition:
        all of them
}