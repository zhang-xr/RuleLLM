rule Suspicious_Executable_Download_URL {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URLs used to download executable files in Python scripts."
        confidence = 85
        severity = 75

    strings:
        $url_pattern = /https?:\/\/[^\s]+\/([^\s\/]+\.exe)/ nocase
        $powershell_command = "powershell -Command" nocase

    condition:
        $url_pattern and $powershell_command
}