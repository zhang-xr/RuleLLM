rule Suspicious_Setup_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious metadata in Python setup scripts"
        confidence = "75"
        severity = "65"

    strings:
        $suspicious_author = "Sanchez Joseph"
        $suspicious_email = /@gov\.org/

    condition:
        $suspicious_author or $suspicious_email
}