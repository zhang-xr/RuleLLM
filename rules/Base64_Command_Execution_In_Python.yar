rule Base64_Command_Execution_In_Python {
    meta:
        author = "RuleLLM"
        description = "Detects base64-decoded command execution in Python code."
        confidence = 80
        severity = 85

    strings:
        $base64_encode = "base64.b64encode"
        $os_system = "os.system"
        $bash_exec = "|base64 -d|bash"

    condition:
        all of them and filesize < 10KB
}