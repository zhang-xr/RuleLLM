rule Suspicious_String_Decoding_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious string decoding patterns often used in malicious scripts to obfuscate payloads or commands."
        confidence = 85
        severity = 80

    strings:
        $decoding_pattern = /''\.join\(\[chr\(\(\(ord\(c\) - \d+ - \d+\) % \d+\) \+ \d+\) for c in .+\]\)/

    condition:
        $decoding_pattern
}