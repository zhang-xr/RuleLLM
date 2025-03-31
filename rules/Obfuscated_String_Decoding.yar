rule Obfuscated_String_Decoding {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated string decoding using base64 and zlib"
        confidence = "92"
        severity = "88"
    
    strings:
        $base64 = "base64.b64decode" ascii wide
        $zlib = "zlib.decompress" ascii wide
        $codecs = "codecs.decode" ascii wide
        $chr_int = "chr(int(" ascii wide
    
    condition:
        all of ($base64, $zlib, $codecs) and 
        any of ($chr_int)
}