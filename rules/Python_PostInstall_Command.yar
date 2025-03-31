rule Python_PostInstall_Command {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files with custom post-install commands that execute malicious code."
        confidence = "95"
        severity = "80"
    strings:
        $setup = "setup("
        $post_install = "cmdclass={'install'"
        $install_class = "class PostInstallCommand"
    condition:
        all of them
}