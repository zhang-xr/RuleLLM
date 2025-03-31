rule Python_Bitsadmin_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using bitsadmin for malicious downloads"
        confidence = 95
        severity = 85
    strings:
        $bitsadmin = "bitsadmin /transfer"
        $http = /https?:\/\/[^\s]+/
        $exe_path = /C:\\[^ ]+\.exe/
        $priority = "/priority FOREGROUND"
    condition:
        $bitsadmin and $http and $exe_path and $priority
}