rule Suspicious_Python_Package_Paths {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages creating suspicious paths"
        confidence = 80
        severity = 70
        
    strings:
        $root_path = "os.path.join(os.path.abspath(os.sep),"
        $user_path = "os.path.join(os.path.expanduser('~'),"
        $filename = "FILENAME = 'ashed'"
        
    condition:
        all of them and
        filesize < 10KB
}