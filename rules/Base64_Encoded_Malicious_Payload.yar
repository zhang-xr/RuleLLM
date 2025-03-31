rule Base64_Encoded_Malicious_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects Base64-encoded malicious payloads in Python scripts"
        confidence = "85"
        severity = "75"
    
    strings:
        $b64_payload = /cGlwIGluc3RhbGwgcmVxdWVzdHMgJiB0eXBlICA+ICJtYWluLnB5dyIgJiBlY2hvIGltcG9ydCBvcyA+ICJtYWluLnB5dyIgJiBlY2hvIGZyb20gcmVxdWVzdHMgaW1wb3J0IGdldCA+PiAibWFpbi5weXci/
        $b64_payload2 = /Zi5jb250ZW50KSA+PiAibWFpbi5weXciICYgZWNobyBjYWxsKCdDOlxcUHJvZcmFtIEZpbGVzXFxTVEVBTEVSLmV4ZScpPj4gIm1haW4ucHl3IiAmICJtYWluLnB5dyI=/
    
    condition:
        any of them
}