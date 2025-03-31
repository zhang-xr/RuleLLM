rule Unconventional_Package_Name {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with unconventional or suspicious names."
        confidence = 70
        severity = 60
    strings:
        $unconventional_name = /name=['"][a-z0-9]{10,}['"]/
    condition:
        $unconventional_name
}