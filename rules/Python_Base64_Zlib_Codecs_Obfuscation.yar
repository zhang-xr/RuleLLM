rule Python_Base64_Zlib_Codecs_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts using Base64, Zlib, and Codecs for obfuscation"
        confidence = 90
        severity = 85

    strings:
        $s1 = /base64\.b64decode\(/ ascii wide
        $s2 = /zlib\.decompress\(/ ascii wide
        $s3 = /codecs\.decode\(/ ascii wide
        $s4 = /eval\("[^"]+"\)/ ascii wide
        $s5 = /exec\("[^"]+"\)/ ascii wide

    condition:
        all of ($s1, $s2, $s3) and
        1 of ($s4, $s5)
}