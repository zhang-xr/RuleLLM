rule Python_Base64_Decode_Execute {
    meta:
        author = "RuleLLM"
        description = "Detects Python malware using Base64 decoding and execution"
        confidence = 90
        severity = 85

    strings:
        $b64decode = "b64decode" nocase
        $exec = "exec" nocase
        $eval = "eval" nocase

    condition:
        $b64decode and 
        (1 of ($exec, $eval))
}