rule Python_Advanced_Obfuscation_Lambda {
    meta:
        author = "RuleLLM"
        description = "Detects advanced Python obfuscation using lambda functions and encoded strings"
        confidence = 95
        severity = 90
    strings:
        $s1 = /_=lambda\s+\w+,\w+=\d+:/
        $s2 = /eval\("".join\(chr\(i\)\s+for\s+i\s+in\s+\[\d+(,\d+)*\]\)\)/
        $s3 = /setattr\(__builtins__,"_{5}",(print|exec|eval)\)/
        $s4 = /base64\.b64decode\(codecs\.decode\(zlib\.decompress\(/
        $s5 = /"\x5f\x5f\x5f\x5f"/
    condition:
        3 of them
}