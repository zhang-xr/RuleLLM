rule Python_ReverseShell_IP_Port {
    meta:
        author = "RuleLLM"
        description = "Detects reverse shell patterns with IP and port in Python code"
        confidence = 98
        severity = 95
    strings:
        $reverse_shell = /bash -i >& \/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5} <&1/
    condition:
        $reverse_shell and 
        filesize < 50KB
}