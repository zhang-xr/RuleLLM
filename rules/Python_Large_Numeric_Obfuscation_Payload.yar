rule Python_Large_Numeric_Obfuscation_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts with large numeric payloads used for obfuscation"
        confidence = 85
        severity = 80

    strings:
        $s1 = /\d{6,7}\s\d{6,7}\s\d{6,7}/ ascii wide
        $s2 = /eval\("[^"]+"\)/ ascii wide
        $s3 = /exec\("[^"]+"\)/ ascii wide
        $s4 = /base64\.b64decode\(/ ascii wide
        $s5 = /zlib\.decompress\(/ ascii wide

    condition:
        all of ($s1, $s2) and
        2 of ($s3, $s4, $s5)
}