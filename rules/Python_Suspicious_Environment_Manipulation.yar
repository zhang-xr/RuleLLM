rule Python_Suspicious_Environment_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that manipulate environment variables to execute commands."
        confidence = 80
        severity = 85
    strings:
        $set_env_pattern = /set\s+\w+=\w+/
        $start_pattern = /start\s+\w+\.exe/
    condition:
        $set_env_pattern and $start_pattern
}