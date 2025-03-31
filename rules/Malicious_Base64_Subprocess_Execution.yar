rule Malicious_Base64_Subprocess_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoded commands being executed via subprocess.Popen"
        confidence = 90
        severity = 80
    strings:
        $b64_decode = "base64.b64decode"
        $subprocess = "subprocess.Popen" 
        $cmd_var = /cmd\s*=/
        $pycmd = /pycmd\s*=/
        $long_b64 = /['"][A-Za-z0-9+\/]{100,}={0,2}['"]/
        $decode_execute = /\.decode\(\)/
    condition:
        all of ($b64_decode, $subprocess) and 
        any of ($cmd_var, $pycmd) and 
        any of ($long_b64, $decode_execute) and 
        filesize < 100KB
}