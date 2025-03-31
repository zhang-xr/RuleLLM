rule PyObfuscate_Compression_Techniques {
    meta:
        author = "RuleLLM"
        description = "Detects the use of compression libraries like zlib in obfuscated Python code"
        confidence = 80
        severity = 70
        
    strings:
        $zlib_import = "import zlib"
        $codecs_import = "import codecs"
        $random_import = "import random"
        $base64_import = "import base64"
        
    condition:
        all of them
}