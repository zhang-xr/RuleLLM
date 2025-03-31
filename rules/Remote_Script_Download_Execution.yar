rule Remote_Script_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects remote script download and execution via curl and sh"
        confidence = 85
        severity = 90
    strings:
        $curl_command = /curl\s+http:\/\/[^\s]+/
        $sh_execution = /\|\s*sh/
    condition:
        $curl_command and $sh_execution
}