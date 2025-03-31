rule Malicious_Setuptools_Command_Override {
    meta:
        author = "RuleLLM"
        description = "Detects malicious overrides of setuptools commands in Python packages"
        confidence = 90
        severity = 80

    strings:
        $setuptools_setup = "setuptools.setup"
        $cmdclass_dict = "cmdclass={"
        $install_override = /class .*\(install\):/
        $develop_override = /class .*\(develop\):/

    condition:
        $setuptools_setup and $cmdclass_dict and
        ($install_override or $develop_override)
}