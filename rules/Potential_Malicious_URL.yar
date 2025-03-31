rule Potential_Malicious_URL {
    meta:
        author = "RuleLLM"
        description = "Detects the presence of a URL that may be used to download additional malicious content."
        confidence = 80
        severity = 75

    strings:
        $suspicious_url = "https://pyobfuscate.com"
        $base64_import = "import base64"
        $codecs_import = "import codecs"
        $zlib_import = "import zlib"

    condition:
        $suspicious_url and any of ($base64_import, $codecs_import, $zlib_import)
}