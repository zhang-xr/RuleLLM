rule Base64_Encoded_Reverse_Shell {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded reverse shell execution in Python scripts."
        confidence = 95
        severity = 100
    strings:
        $base64_encode = "base64.b64encode"
        $base64_decode = /base64\s*-d/
        $bash_execution = /echo\s*%.*\|base64\s*-d\|bash/
    condition:
        all of ($base64_encode, $base64_decode, $bash_execution)
}