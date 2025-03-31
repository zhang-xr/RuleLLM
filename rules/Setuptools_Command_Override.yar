rule Setuptools_Command_Override {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setuptools command overrides with post-execution hooks"
        confidence = 90
        severity = 85
    strings:
        $cmdclass = "cmdclass={"
        $install_override = "install': AfterInstall"
        $develop_override = "develop': AfterDevelop"
        $run_method = "def run(self):"
    condition:
        all of ($cmdclass, $run_method) and
        any of ($install_override, $develop_override)
}