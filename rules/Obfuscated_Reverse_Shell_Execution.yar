rule Obfuscated_Reverse_Shell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated reverse shell execution via base64 encoding in Python scripts"
        confidence = 95
        severity = 100
    strings:
        $base64_encode = "base64.b64encode("
        $os_system = "os.system("
        $bash_exec = "|bash"
    condition:
        all of ($base64_encode, $os_system, $bash_exec)
}