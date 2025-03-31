rule Malicious_Python_Startup_Clone {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that creates a startup folder and clones a GitHub repository for persistence"
        confidence = 90
        severity = 85

    strings:
        $startup_path = /C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup/
        $git_clone = "git.Git(" nocase
        $os_makedirs = "os.makedirs(" nocase
        $os_rename = "os.rename(" nocase
        $github_url = /https:\/\/github\.com\/.*\.git/ nocase

    condition:
        all of them and
        filesize < 10KB
}