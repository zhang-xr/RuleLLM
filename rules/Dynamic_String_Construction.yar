rule Dynamic_String_Construction {
    meta:
        author = "RuleLLM"
        description = "Detects dynamic string construction using chr() and join()"
        confidence = 85
        severity = 80

    strings:
        $chr_pattern = /chr\s*\(\s*\d+\s*\)/
        $join_pattern = /\.join\s*\(.*\)/

    condition:
        $chr_pattern and $join_pattern
}