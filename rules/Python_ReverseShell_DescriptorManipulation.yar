rule Python_ReverseShell_DescriptorManipulation {
    meta:
        author = "RuleLLM"
        description = "Detects file descriptor manipulation for reverse shells"
        confidence = 92
        severity = 88
    
    strings:
        $dup2_pattern = "os.dup2(s.fileno(),"
        $fileno = "s.fileno()"
        $std_patterns = /\b(0|1|2)\b/
        
    condition:
        $dup2_pattern and $fileno and
        2 of ($std_patterns)
}