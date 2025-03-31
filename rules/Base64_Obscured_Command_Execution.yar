rule Base64_Obscured_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoded command execution patterns"
        confidence = 90
        severity = 85
    strings:
        $base64_encode = "base64.b64encode" nocase
        $base64_decode = "base64 -d" nocase
        $system_exec = "os.system" nocase
        $bash_exec = "|bash" nocase
    condition:
        all of ($base64_encode, $system_exec) and 
        any of ($base64_decode, $bash_exec)
}