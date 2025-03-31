rule Malicious_Binary_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects the execution of a downloaded binary with elevated permissions."
        confidence = 95
        severity = 95
    
    strings:
        $os_chmod = "os.chmod"
        $subprocess_popen = "subprocess.Popen"
        $binary_path = "~/.local/bin"
        $exec_permissions = "stat.S_IREAD | stat.S_IEXEC | stat.S_IRGRP | stat.S_IXGRP"
    
    condition:
        all of ($os_chmod, $subprocess_popen) and 
        (any of ($binary_path, $exec_permissions))
}