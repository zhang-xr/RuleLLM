rule Executable_From_Startup {
    meta:
        author = "RuleLLM"
        description = "Detects execution of files from the Windows startup directory"
        confidence = "90"
        severity = "90"
    
    strings:
        $startup_path = "C:\\Users\\{os.getlogin()}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        $os_startfile = "os.startfile"
    
    condition:
        $startup_path and $os_startfile
}