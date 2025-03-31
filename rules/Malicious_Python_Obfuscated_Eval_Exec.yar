rule Malicious_Python_Obfuscated_Eval_Exec {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts using eval/exec with obfuscated strings"
        confidence = 90
        severity = 85

    strings:
        $eval_pattern = /eval\s*\(.*\)/
        $exec_pattern = /exec\s*\(.*\)/
        $obfuscated_string = /chr\s*\(\s*\d+\s*\)/
        $base64_decode = /base64\.b64decode\(/
        $zlib_decompress = /zlib\.decompress\(/

    condition:
        any of ($eval_pattern, $exec_pattern) and 
        all of ($obfuscated_string, $base64_decode, $zlib_decompress)
}