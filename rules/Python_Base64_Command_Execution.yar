rule Python_Base64_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoded command execution patterns in Python"
        confidence = 85
        severity = 90
        reference = "Analyzed code segment"
    
    strings:
        $base64_encode = "base64.b64encode"
        $os_system = "os.system"
        $bash_exec = /echo\s+%.*\|base64\s+-d\|bash/
    
    condition:
        all of ($base64_encode, $os_system) and $bash_exec
}