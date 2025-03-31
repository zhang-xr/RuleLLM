rule XOR_Encryption_Binary_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects XOR encryption patterns and subsequent binary execution"
        confidence = "85"
        severity = "85"
    
    strings:
        $xor_pattern = "for b, k in zip("
        $binary_write = "with open(binary_path, 'wb') as f:"
        $exec_permission = "os.chmod(binary_path, stat.S_IREAD | stat.S_IEXEC"
        $binary_exec = "subprocess.Popen([binary_path]"
    
    condition:
        all of them
}