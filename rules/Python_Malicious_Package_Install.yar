rule Python_Malicious_Package_Install {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages that execute code during installation"
        confidence = 90
        severity = 80
    strings:
        $setup_py = "from setuptools import setup"
        $post_install = "class PostInstallCommand(install):"
        $cmd_class = "cmdclass={'install' : PostInstallCommand,}"
    condition:
        all of them
}