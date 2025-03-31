rule Python_Suspicious_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious metadata in Python package setup"
        confidence = 80
        severity = 70
    strings:
        $suspicious_email = /author_email\s*=\s*['\"].*@vulnium\.com['\"]/
        $google_url = /url\s*=\s*['\"]https:\/\/google\.com['\"]/
    condition:
        filesize < 10KB and
        any of them
}