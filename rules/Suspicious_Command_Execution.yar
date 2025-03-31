rule Suspicious_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious command execution through subprocess"
        confidence = 90
        severity = 85
        
    strings:
        $subprocess_check_output = "subprocess.check_output"
        $shell_true = "shell=True"
        $getmac = /['"][gG]etmac['"]/
        $ifconfig = /['"][iI]fconfig['"]/
        
    condition:
        all of ($subprocess_check_output, $shell_true) and 1 of ($getmac, $ifconfig)
}