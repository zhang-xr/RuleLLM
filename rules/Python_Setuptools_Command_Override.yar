rule Python_Setuptools_Command_Override {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setuptools command overrides that could execute malicious code"
        confidence = 85
        severity = 75
    strings:
        $install_override = "class AfterInstall(install):" ascii
        $develop_override = "class AfterDevelop(develop):" ascii
        $cmdclass = "cmdclass={" ascii
        $run_method = "def run(self):" ascii
    condition:
        ($install_override or $develop_override) and $cmdclass and $run_method
}