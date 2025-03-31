rule Hidden_Binary_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects patterns of hidden binary execution in Python scripts"
        confidence = 90
        severity = 95
    
    strings:
        $subprocess_popen = "subprocess.Popen("
        $stdout_null = "stdout=subprocess.DEVNULL"
        $stderr_redirect = "stderr=subprocess.STDOUT"
        $os_chmod_exec = "os.chmod(.*stat.S_IEXEC"
        $local_bin_path = /\.local\/bin/
    
    condition:
        all of ($subprocess_popen, $stdout_null) and
        any of ($stderr_redirect, $os_chmod_exec) and
        $local_bin_path
}