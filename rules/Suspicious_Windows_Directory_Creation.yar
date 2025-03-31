rule Suspicious_Windows_Directory_Creation {
    meta:
        author = "RuleLLM"
        description = "Detects creation of suspicious Windows directories"
        confidence = "85"
        severity = "75"
    
    strings:
        $win_path1 = "C:\\Windows\\Users\\"
        $win_path2 = "\\Desktop\\"
        $hack_dir = "HACK_"
        $mkdir = "mkdir"
    
    condition:
        $mkdir and 
        ($win_path1 or $win_path2) and 
        $hack_dir and 
        filesize < 10KB
}