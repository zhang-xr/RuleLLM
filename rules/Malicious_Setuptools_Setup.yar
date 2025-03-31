rule Malicious_Setuptools_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setuptools setup with post-install command"
        confidence = 90
        severity = 85

    strings:
        $setup_call = "setup("
        $cmdclass = "cmdclass={"
        $post_install = "'install': PostInstallCommand"
        $install_requires = "install_requires=["

    condition:
        all of ($setup_call, $cmdclass, $post_install) and
        $install_requires
}