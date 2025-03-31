rule GitHub_Clone_In_Startup {
    meta:
        author = "RuleLLM"
        description = "Detects cloning of GitHub repositories into the Windows startup directory"
        confidence = "85"
        severity = "80"
    
    strings:
        $startup_path = "C:\\Users\\{os.getlogin()}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        $git_clone = "git.Git(repoDirectory).clone(gitUrl)"
    
    condition:
        $startup_path and $git_clone
}