rule Suspicious_FilePaths_UserInfo {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious file paths and user information collection patterns"
        confidence = 80
        severity = 75
    
    strings:
        $root_path = "os.path.join(os.path.abspath(os.sep)"
        $user_path = "os.path.join(os.path.expanduser('~')"
        $getuser = "getpass.getuser()"
        $filename = "'LMAO'"
    
    condition:
        all of ($root_path, $user_path, $getuser, $filename)
}