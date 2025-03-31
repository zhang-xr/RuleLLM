rule Hidden_Process_Creation {
    meta:
        author = "RuleLLM"
        description = "Detects hidden process creation patterns commonly used in malware"
        confidence = "85"
        severity = "90"
    
    strings:
        $creationflags = "CREATE_NO_WINDOW"
        $hidden_window = "-WindowStyle Hidden"
        $shell_false = "shell=False"
    
    condition:
        all of them
}