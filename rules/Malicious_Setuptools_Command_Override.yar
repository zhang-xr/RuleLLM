rule Malicious_Setuptools_Command_Override {
    meta:
        author = "RuleLLM"
        description = "Detects malicious override of setuptools install/develop commands"
        confidence = 85
        severity = 75
    strings:
        $install_override = /class\s+\w+\(install\):/
        $develop_override = /class\s+\w+\(develop\):/
        $cmdclass = "cmdclass"
        $setuptools_setup = "setuptools.setup"
    condition:
        all of ($install_override, $develop_override, $cmdclass, $setuptools_setup)
}