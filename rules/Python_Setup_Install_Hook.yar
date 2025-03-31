rule Python_Setup_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files with custom install hooks that could execute arbitrary code during installation"
        confidence = 90
        severity = 80
    strings:
        $class_def = "class PostInstallCommand" nocase
        $install_hook = "cmdclass={'install'" nocase
        $setuptools_import = "from setuptools" nocase
    condition:
        all of them
}