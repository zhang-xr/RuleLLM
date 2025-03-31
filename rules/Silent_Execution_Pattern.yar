rule Silent_Execution_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects silent execution patterns using PowerShell's Start-Process"
        confidence = 85
        severity = 80
    strings:
        $start_process = "Start-Process"
        $no_new_window = "-NoNewWindow"
        $wait_flag = "-Wait"
        $powershell = "powershell"
        $exe_file = /"[^"]+\.exe"/
    condition:
        all of them and 
        #start_process > 1
}