rule Custom_Install_Command_Override {
    meta:
        author = "RuleLLM"
        description = "Detects custom install command overrides in Python setup scripts"
        confidence = 95
        severity = 85

    strings:
        $class_definition = /class\s+\w+Install\(install\):/
        $run_method = /def\s+run\(self\):/
        $cmdclass = /cmdclass\s*=\s*{/

    condition:
        all of them
}