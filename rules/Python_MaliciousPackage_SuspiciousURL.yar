rule Python_MaliciousPackage_SuspiciousURL {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts containing suspicious URLs."
        confidence = 85
        severity = 75

    strings:
        $suspicious_url = /https?:\/\/[a-z0-9\-\.]+\.[a-z]{2,}\/[a-z0-9\-\.\/]+\.html/

    condition:
        $suspicious_url and filesize < 10KB
}