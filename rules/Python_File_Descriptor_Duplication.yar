rule Python_File_Descriptor_Duplication {
    meta:
        author = "RuleLLM"
        description = "Detects Python code duplicating file descriptors using os.dup2"
        confidence = 80
        severity = 75

    strings:
        $dup2_0 = "os.dup2(s.fileno(), 0)"
        $dup2_1 = "os.dup2(s.fileno(), 1)"
        $dup2_2 = "os.dup2(s.fileno(), 2)"

    condition:
        any of ($dup2_0, $dup2_1, $dup2_2)
}