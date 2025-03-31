rule Malicious_Python_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts using obfuscation techniques commonly associated with malicious behavior"
        confidence = 90
        severity = 85

    strings:
        $base64_import = "base64"
        $zlib_import = "zlib"
        $codecs_import = "codecs"
        $obfuscate_string = /obfuscate\s*=\s*dict\(map\(lambda\s*map,dict:\(map,dict\)/
        $pyobfuscate_reference = "pyobfuscate.com"

    condition:
        all of ($base64_import, $zlib_import, $codecs_import) and 
        any of ($obfuscate_string, $pyobfuscate_reference)
}