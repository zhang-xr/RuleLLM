rule Long_Obfuscated_String {
    meta:
        author = "RuleLLM"
        description = "Detects long, obfuscated strings commonly used in malware"
        confidence = 95
        severity = 85

    strings:
        $long_string = /[\x20-\x7E]{100,}/

    condition:
        $long_string
}