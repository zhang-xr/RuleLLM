rule Python_Complex_Encoding_Chain {
    meta:
        author = "RuleLLM"
        description = "Detects complex encoding/decoding chains using multiple techniques"
        confidence = 85
        severity = 80
    strings:
        $s1 = /base64\.b64decode\(codecs\.decode\(zlib\.decompress\(/
        $s2 = /"".join\(chr\(int\(i\/\d+\)\)\s+for\s+i\s+in\s+\[\d+(,\d+)*\]\)/
        $s3 = /\.decode\("".join\(chr\(int\(i\/\d+\)\)\s+for\s+i\s+in\s+\[\d+(,\d+)*\]\)\)/
        $s4 = /\.encode\(\)\)\)\)\)/
    condition:
        3 of them
}