rule Custom_PostInstall_Command {
    meta:
        author = "RuleLLM"
        description = "Detects Python script using a custom post-install command for malicious execution."
        confidence = 90
        severity = 85

    strings:
        $post_install_class = "class PostInstallCommand"
        $setup_cmdclass = "cmdclass={'install': PostInstallCommand}"
        $setuptools_import = "from setuptools import setup"

    condition:
        all of them and filesize < 10KB
}