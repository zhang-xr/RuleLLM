rule Python_Suspicious_Setup_Config {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious configuration patterns in Python setup scripts"
        confidence = 80
        severity = 70
    strings:
        $empty_desc = "description=''"
        $suspicious_url = /url=['"]https:\/\/[^\/]+\.(org|me)/
        $suspicious_email = /author_email=['"][^@]+@[^\.]+\.(me|xyz)/
        $requests_dep = "'requests'"
    condition:
        3 of them and 
        filesize < 10KB
}