rule Suspicious_String_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious string manipulation using chr, join, and list comprehensions"
        confidence = 85
        severity = 80

    strings:
        $chr_pattern = "chr"
        $join_pattern = "join"
        $list_comp_pattern = /for\s+\w+\s+in\s+\[/

    condition:
        all of them
}