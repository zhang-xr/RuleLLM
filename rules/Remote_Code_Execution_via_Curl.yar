rule Remote_Code_Execution_via_Curl {
    meta:
        author = "RuleLLM"
        description = "Detects patterns of remote code execution via curl and shell piping."
        confidence = 95
        severity = 90

    strings:
        $curl_execution = /curl\s+http:\/\/[^\s]+\s*\|sh/
        $os_system = "os.system"

    condition:
        $curl_execution and $os_system
}