rule Suspicious_Encoded_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects encoded commands being executed with platform checks"
        confidence = 95
        severity = 90
    strings:
        $base64_decode = "base64.b64decode"
        $subprocess = "subprocess.Popen"
        $long_b64 = /['"][A-Za-z0-9+\/]{100,}={0,2}['"]/
        $decode_execute = /\.decode\(\)/
        $platform_check = "platform.system()"
    condition:
        all of ($base64_decode, $subprocess, $platform_check) and 
        any of ($long_b64, $decode_execute) and 
        filesize < 100KB
}