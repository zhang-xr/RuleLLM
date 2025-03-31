rule Malicious_Python_Payload_Decoding {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using base64 and zlib to decode payloads."
        confidence = "85"
        severity = "90"

    strings:
        $base64 = "base64.b64decode"
        $zlib = "zlib.decompress"
        $codecs = "codecs.decode"
        $eval = "eval"
        $exec = "exec"

    condition:
        all of ($base64, $zlib) and 
        any of ($eval, $exec) and
        $codecs
}