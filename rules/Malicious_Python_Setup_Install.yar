rule Malicious_Python_Setup_Install {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup scripts that install additional components during installation"
        confidence = "90"
        severity = "85"
    
    strings:
        $install_class = "class CustomInstallCommand(install):"
        $os_env = "os.environ[\"GIT_PYTHON_REFRESH\"] = \"quiet\""
        $git_import = "import git"
        $startup_path = "C:\\Users\\{os.getlogin()}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        $git_clone = "git.Git(repoDirectory).clone(gitUrl)"
        $os_startfile = "os.startfile"
    
    condition:
        all of them
}