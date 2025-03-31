rule Suspicious_Setup_Description {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious package descriptions in Python setup files"
        confidence = 80
        severity = 70

    strings:
        $random_description = /DESCRIPTION = '[\w\s]{20,}'/
        $long_random_description = /LONG_DESCRIPTION = '[\w\s]{50,}'/

    condition:
        $random_description and $long_random_description
}