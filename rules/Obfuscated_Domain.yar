rule Obfuscated_Domain {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated domains in HTTP requests"
        confidence = 95
        severity = 85
    strings:
        // Regex for obfuscated domains (long alphanumeric strings)
        $s1 = /http:\/\/[a-z0-9]{20,}\.[a-z0-9]{2,3}\//
    condition:
        $s1
}