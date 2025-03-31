rule Suspicious_Hardcoded_URL {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded URLs pointing to executable files on GitHub or other suspicious domains"
        confidence = 85
        severity = 80

    strings:
        $github_url = /https:\/\/github\.com\/[^\/]+\/[^\/]+\/raw\/main\/[^\.]+\.exe/
        $suspicious_url = /https?:\/\/[^\s]+\.exe/

    condition:
        any of them and
        filesize < 10KB
}