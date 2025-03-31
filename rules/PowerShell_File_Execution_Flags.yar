rule PowerShell_File_Execution_Flags {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands used to execute downloaded files with specific flags"
        confidence = 85
        severity = 75

    strings:
        $powershell_exec = "subprocess.run([\"powershell\", \"-Command\""
        $start_process = "Start-Process"
        $no_new_window = "-NoNewWindow"
        $wait_flag = "-Wait"

    condition:
        all of ($powershell_exec, $start_process) and
        any of ($no_new_window, $wait_flag)
}