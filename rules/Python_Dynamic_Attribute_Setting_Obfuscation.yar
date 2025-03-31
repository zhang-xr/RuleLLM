rule Python_Dynamic_Attribute_Setting_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts dynamically setting attributes for built-ins with obfuscation"
        confidence = 95
        severity = 90

    strings:
        $s1 = /setattr\(__builtins__/ ascii wide
        $s2 = /eval\("[^"]+"\)/ ascii wide
        $s3 = /exec\("[^"]+"\)/ ascii wide
        $s4 = /base64\.b64decode\(/ ascii wide
        $s5 = /zlib\.decompress\(/ ascii wide

    condition:
        all of ($s1, $s2) and
        2 of ($s3, $s4, $s5)
}