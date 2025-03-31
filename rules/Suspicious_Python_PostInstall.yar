rule Suspicious_Python_PostInstall {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with custom post-install commands"
        confidence = "85"
        severity = "75"

    strings:
        $setup_import = "from setuptools import setup"
        $post_install_class = /class\s+\w+\(install\):/
        $post_install_call = /install\.run\(self\)\s+\w+\(\)/

    condition:
        $setup_import and $post_install_class and $post_install_call
}