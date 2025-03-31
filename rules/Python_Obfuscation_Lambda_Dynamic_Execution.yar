rule Python_Obfuscation_Lambda_Dynamic_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using lambda functions for obfuscation and dynamic code execution"
        confidence = 95
        severity = 90

    strings:
        $s1 = /_=lambda\s+[^\s]+,c_int=\d+:/ ascii wide
        $s2 = /eval\("[^"]+"\)/ ascii wide
        $s3 = /exec\("[^"]+"\)/ ascii wide
        $s4 = /base64\.b64decode\(/ ascii wide
        $s5 = /codecs\.decode\(/ ascii wide
        $s6 = /zlib\.decompress\(/ ascii wide
        $s7 = /setattr\(__builtins__/ ascii wide

    condition:
        all of ($s1, $s2, $s7) and
        2 of ($s3, $s4, $s5, $s6)
}