rule Compression_Library_Usage {
    meta:
        author = "RuleLLM"
        description = "Detects the use of compression libraries like zlib in Python scripts"
        confidence = 80
        severity = 70

    strings:
        $zlib_pattern = "zlib"

    condition:
        $zlib_pattern
}