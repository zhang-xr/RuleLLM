rule Python_Setuptools_Malicious_Override {
    meta:
        author = "RuleLLM"
        description = "Detects malicious overrides of setuptools commands (install/develop) to execute additional code."
        confidence = 85
        severity = 75

    strings:
        $install_override = "class AfterInstall(install):" nocase
        $develop_override = "class AfterDevelop(develop):" nocase
        $cmdclass = "cmdclass={" nocase
        $run_method = "def run(self):" nocase

    condition:
        (1 of ($install_override, $develop_override)) and
        $cmdclass and
        $run_method
}