rule Malicious_Python_Obfuscated_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated payloads in Python scripts"
        confidence = 85
        severity = 80

    strings:
        $base64_pattern = /base64\.b64decode\(/
        $zlib_pattern = /zlib\.decompress\(/
        $chr_pattern = /chr\s*\(\s*\d+\s*\)/
        $exec_pattern = /exec\s*\(.*\)/

    condition:
        all of ($base64_pattern, $zlib_pattern, $chr_pattern) and 
        $exec_pattern
}