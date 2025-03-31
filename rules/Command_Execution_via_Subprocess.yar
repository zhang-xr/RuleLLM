rule Command_Execution_via_Subprocess {
    meta:
        author = "RuleLLM"
        description = "Detects execution of system commands via subprocess module"
        confidence = 80
        severity = 75

    strings:
        $subprocess = "subprocess" ascii
        $check_output = "check_output" ascii
        $shell_true = "shell=True" ascii
        $getmac = "getmac" ascii
        $ifconfig = "ifconfig" ascii

    condition:
        all of ($subprocess, $check_output, $shell_true) and 
        any of ($getmac, $ifconfig)
}