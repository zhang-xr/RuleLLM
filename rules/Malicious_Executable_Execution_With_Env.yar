rule Malicious_Executable_Execution_With_Env {
    meta:
        author = "RuleLLM"
        description = "Detects execution of executables with environment variable manipulation"
        confidence = 80
        severity = 70

    strings:
        $env_pattern = /set\s+__\w+=\w+/
        $exec_pattern = /start\s+\w+\.exe/

    condition:
        $env_pattern and $exec_pattern
}