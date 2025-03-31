rule Suspicious_Setup_Empty_Fields {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with empty author and email fields."
        confidence = 75
        severity = 65
    strings:
        $empty_author = "author=\"\""
        $empty_email = "author_email=\"\""
    condition:
        $empty_author and $empty_email
}