rule Python_InstallHook_Abuse {
    meta:
        author = "RuleLLM"
        description = "Detects abuse of setuptools install hooks for malicious purposes"
        confidence = 95
        severity = 85
    strings:
        $setuptools_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $install_hook = /class\s+\w+\(install\):/
        $cmdclass = /cmdclass\s*=\s*{.*'install'\s*:/
    condition:
        all of them
}