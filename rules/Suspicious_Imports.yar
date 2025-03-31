rule Suspicious_Imports {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious import statements"
        confidence = 80
        severity = 70

    strings:
        $import_random = "import random" ascii
        $import_base64 = "import base64" ascii
        $import_codecs = "import codecs" ascii
        $import_zlib = "import zlib" ascii

    condition:
        any of them
}