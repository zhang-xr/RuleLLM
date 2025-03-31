rule Base64_Encoded_Strings {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded strings in Python scripts"
        confidence = "75"
        severity = "70"
    
    strings:
        $base64_major = "b3JhbmRvbTExNS5"
        $base64_minor = "jc3BocTVkNi55YW5"
        $base64_patch = "raXoub25saW5l"
    
    condition:
        any of them
}