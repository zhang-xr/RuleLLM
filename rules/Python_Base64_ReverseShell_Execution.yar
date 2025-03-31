rule Python_Base64_ReverseShell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded reverse shell execution in Python scripts"
        confidence = 85
        severity = 90

    strings:
        $base64_encode = "base64.b64encode("
        $os_system = "os.system("
        $bash_exec = "|base64 -d|bash"

    condition:
        all of them
}