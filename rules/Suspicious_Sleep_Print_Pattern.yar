rule Suspicious_Sleep_Print_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious use of sleep and print statements"
        confidence = 80
        severity = 70
    strings:
        $sleep = "sleep("
        $print = "print("
        $install_message = /Installation\s+completed\[OK\]/
    condition:
        all of them
}