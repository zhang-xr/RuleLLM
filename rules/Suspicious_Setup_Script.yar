rule Suspicious_Setup_Script {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup scripts with potential malicious intent"
        confidence = 85
        severity = 90

    strings:
        $setup_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $post_install_class = /class\s+\w+\(install\):/
        $install_run = "install.run(self)"
        $custom_command = /cmdclass\s*=\s*\{[^']*'install':\s*\w+\}/

    condition:
        all of ($setup_import, $install_import, $post_install_class, $install_run) and
        $custom_command
}