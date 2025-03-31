rule Python_Setuptools_PostInstall_Abuse {
    meta:
        author = "RuleLLM"
        description = "Detects abuse of setuptools post-install command for malicious purposes"
        confidence = 85
        severity = 80
    strings:
        $install_import = "from setuptools.command.install import install"
        $custom_cmdclass = "cmdclass = {"
        $post_install_class = "class PostInstallCommand"
        $install_run = "install.run(self)"
    condition:
        all of them and filesize < 10KB
}