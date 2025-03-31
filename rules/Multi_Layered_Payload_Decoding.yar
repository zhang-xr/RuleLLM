rule Multi_Layered_Payload_Decoding {
    meta:
        author = "RuleLLM"
        description = "Detects multi-layered payload decoding using Base64 and custom encoding."
        confidence = 95
        severity = 90

    strings:
        $b64decode = "b64decode("
        $decode = ".decode("
        $custom_decode = /\.decode\(['"][a-z0-9]{2,}['"]\)/
        $payload_execution = /exec\(.*\.decode\(.*\)\)/

    condition:
        $b64decode and 
        ($decode or $custom_decode) and 
        $payload_execution
}