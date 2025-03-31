rule Obfuscated_URL_Download {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated URL construction in Python code"
        confidence = 85
        severity = 70
    strings:
        $chr_sequence = /\[(\d+, )+\d+\]/
        $url_join = "''.join"
    condition:
        $chr_sequence and $url_join
}