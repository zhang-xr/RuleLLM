rule Python_Obfuscation_Dynamic_Dict_Mapping {
    meta:
        author = "RuleLLM"
        description = "Detects dynamic dictionary mapping used for obfuscation in Python code"
        confidence = 85
        severity = 80

    strings:
        $s1 = "obfuscate = dict(map(lambda map,dict:(map,dict)," ascii wide
        $s2 = "pyobfuscate=" ascii wide
        $s3 = "import random ,base64,codecs,zlib" ascii wide

    condition:
        all of ($s1, $s2, $s3)
}