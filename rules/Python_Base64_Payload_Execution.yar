rule Python_Base64_Payload_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded payload execution in Python code"
        confidence = "95"
        severity = "90"
    
    strings:
        $base64 = "base64.b64decode"
        $exec_family = /(eval|exec)\(/
        $payload = /eJ[\w\+\/=]+/
    
    condition:
        $base64 and 
        $exec_family and 
        $payload
}