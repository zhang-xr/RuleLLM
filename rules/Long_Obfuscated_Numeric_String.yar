rule Long_Obfuscated_Numeric_String {
    meta:
        author = "RuleLLM"
        description = "Detects long, obfuscated numeric strings commonly used in malware"
        confidence = 90
        severity = 85

    strings:
        $long_numeric_string = /\d{6,}\s\d{6,}\s\d{6,}\s\d{6,}\s\d{6,}/

    condition:
        $long_numeric_string
}