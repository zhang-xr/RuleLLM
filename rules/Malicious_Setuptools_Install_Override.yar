rule Malicious_Setuptools_Install_Override {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setuptools setup with overridden install command"
        confidence = 90
        severity = 85

    strings:
        $cmdclass = "cmdclass={"
        $install = "install\":"
        $run_method = "def run(self):"

    condition:
        $cmdclass and $install and $run_method
}