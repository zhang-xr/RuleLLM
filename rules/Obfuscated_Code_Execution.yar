rule Obfuscated_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated code execution patterns using base64, zlib, and dynamic evaluation"
        confidence = "90"
        severity = "85"
    
    strings:
        $base64_decode = "base64.b64decode" ascii wide
        $zlib_decompress = "zlib.decompress" ascii wide
        $codecs_decode = "codecs.decode" ascii wide
        $eval = "eval" ascii wide
        $exec = "exec" ascii wide
        $chr_join = "\"\".join(chr(int(i))" ascii wide
        $lambda_obfuscate = "lambda OO00000OOO0000OOO" ascii wide
    
    condition:
        all of ($base64_decode, $zlib_decompress, $codecs_decode) and 
        any of ($eval, $exec) and 
        any of ($chr_join, $lambda_obfuscate)
}