rule PowerShell_File_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands to execute downloaded files"
        confidence = 95
        severity = 90

    strings:
        $start_process = "Start-Process"
        $powershell_cmd = "powershell"
        $output_file = /output_file\s*=\s*os\.path\.join\(.*\)/

    condition:
        all of ($start_process, $powershell_cmd) and 
        $output_file
}