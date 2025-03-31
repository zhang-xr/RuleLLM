rule Remote_Code_Execution_via_TempFile {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that writes and executes remote code via a temporary file"
        confidence = 95
        severity = 90
    strings:
        $tempfile_write = "_ttmp.write(b\"\"\""
        $urlopen_exec = "exec(_uurlopen"
        $system_exec = "_ssystem(f\"start"
    condition:
        all of ($tempfile_write, $urlopen_exec) and
        any of ($system_exec)
}