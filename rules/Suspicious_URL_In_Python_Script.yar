rule Suspicious_URL_In_Python_Script {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts containing URLs pointing to executable files"
        confidence = 90
        severity = 85

    strings:
        $url_pattern = /https?:\/\/[^\s\/$.?#].[^\s]*\.(exe|dll|bat|cmd|ps1)/

    condition:
        $url_pattern
}