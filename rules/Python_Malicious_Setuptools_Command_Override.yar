rule Python_Malicious_Setuptools_Command_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that override setuptools commands to execute malicious code during package installation."
        confidence = 85
        severity = 90
    strings:
        $class_pattern = /class\s+\w+\(develop|install\):/
        $execute_call = /execute\(\)/
        $cmdclass_pattern = /cmdclass\s*=\s*{.+}/
    condition:
        all of them
}