rule Python_StealthyCodeExecution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using temporary files for stealthy execution"
        confidence = "85"
        severity = "85"
    
    strings:
        $tempfile2 = "NamedTemporaryFile"
        $write2 = ".write("
        $exec2 = "exec("
        $system2 = "system("
        $start1 = "start "
        
    condition:
        all of ($tempfile2, $write2) and 
        2 of ($exec2, $system2, $start1)
}