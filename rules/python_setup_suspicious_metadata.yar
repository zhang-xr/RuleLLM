rule python_setup_suspicious_metadata {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious package metadata in Python setup scripts, such as typosquatting or unusual names."
        confidence = 80
        severity = 70

    strings:
        $suspicious_name = /(sal[aeiou]m[aeiou]s|typo|vuln|zer0ul)/ nocase wide ascii
        $suspicious_author = /(zer0ul|vulnium)/ nocase wide ascii
        $suspicious_email = /(@vulnium\.com)/ nocase wide ascii
        $setup_func = "setup(" nocase wide ascii

    condition:
        ($suspicious_name or $suspicious_author or $suspicious_email) and $setup_func
}