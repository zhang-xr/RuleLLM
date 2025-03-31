rule Remote_Code_Execution_URL {
    meta:
        author = "RuleLLM"
        description = "Detects URLs used for remote code execution in Python scripts."
        confidence = 95
        severity = 100

    strings:
        $url_pattern = /https?:\/\/[^\s]+\/paste\/[^\s]+\/raw/

    condition:
        $url_pattern
}