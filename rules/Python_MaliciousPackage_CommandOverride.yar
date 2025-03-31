rule Python_MaliciousPackage_CommandOverride {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that override the install command to execute custom code."
        confidence = 95
        severity = 90

    strings:
        $cmdclass = "cmdclass={'install'"
        $post_install = "PostInstallCommand"
        $install_import = "from setuptools.command.install import install"

    condition:
        all of them and filesize < 10KB
}