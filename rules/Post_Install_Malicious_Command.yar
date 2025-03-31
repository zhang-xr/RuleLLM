rule Post_Install_Malicious_Command {
    meta:
        author = "RuleLLM"
        description = "Detects custom post-install commands used to execute malicious code"
        confidence = 80
        severity = 70
    strings:
        $post_install_class = "class PostInstallCommand"
        $cmdclass = "cmdclass={'install': PostInstallCommand}"
    condition:
        all of ($post_install_class, $cmdclass)
}