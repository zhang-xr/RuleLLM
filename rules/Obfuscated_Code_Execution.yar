rule Obfuscated_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated code execution patterns using eval/exec and base64/zlib decoding"
        confidence = 90
        severity = 80

    strings:
        $eval_pattern = "eval("
        $exec_pattern = "exec("
        $base64_decode = "base64.b64decode("
        $zlib_decompress = "zlib.decompress("
        $codecs_decode = "codecs.decode("
        $chr_int_pattern = /chr\(int\([^)]+\)\)/

    condition:
        any of ($eval_pattern, $exec_pattern) and 
        any of ($base64_decode, $zlib_decompress, $codecs_decode) and 
        $chr_int_pattern
}