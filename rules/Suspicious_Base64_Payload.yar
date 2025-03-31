rule Suspicious_Base64_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded payloads with zlib decompression"
        confidence = 95
        severity = 90

    strings:
        $base64_payload = "eJw9kN1ygjAUhF8JIkzlMo6mEnIcHVIM3AGtoPIT2wSSPH0p7fTu252d2T3n3MkyK896dLvrSMIeaGxEGn0l/rpiLu3hlXm5yxDmO8tQZIDoeUQLr4oWePxk8VZfBpr9af8mXdzLTk8swRbP25bNzPvP8qwWJDRA8RX4vhLkfvuk0QRl3DOUekDC9xHZFvBccUnXY7mtBrIOBDEKXNRl3KiBBor25l5MN7U5qSA/HsJiVpfsVIQ/Hj4dgoSYOndx+7tZLZ2m3qA4AFpUD6RDsbLXB2m0dPuPZa8GblvoGm/gthdI+8PxyYvnXqRLl9uiJi+xBbqtCmKm8/K3b7hsbmQ="
        $zlib_decompress = "zlib.decompress("
        $base64_decode = "base64.b64decode("

    condition:
        $base64_payload and 
        $zlib_decompress and 
        $base64_decode
}