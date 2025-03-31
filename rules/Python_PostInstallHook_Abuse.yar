rule Python_PostInstallHook_Abuse {
    meta:
        author = "RuleLLM"
        description = "Detects malicious use of setuptools post-install hooks"
        confidence = 90
        severity = 85
    strings:
        $install_class = "class PostInstallCommand"
        $install_import = "from setuptools.command.install import install"
        $cmdclass = "cmdclass"
        $run_method = "def run("
    condition:
        all of ($install_class, $install_import, $cmdclass) and 
        $run_method in (0..500)
}