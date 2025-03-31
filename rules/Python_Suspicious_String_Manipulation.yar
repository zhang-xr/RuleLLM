rule Python_Suspicious_String_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts with suspicious string manipulation techniques"
        confidence = 90
        severity = 85

    strings:
        $s1 = /'\x5f\x5f\x5f\x5f'/ ascii wide
        $s2 = /'\x69\x6e\x28\x63\x68\x72\x28\x69\x29\x20\x66\x6f'/ ascii wide
        $s3 = /'\x28\x22\x22\x2e\x6a\x6f'/ ascii wide
        $s4 = /eval\("[^"]+"\)/ ascii wide
        $s5 = /exec\("[^"]+"\)/ ascii wide

    condition:
        all of ($s1, $s2, $s3) and
        1 of ($s4, $s5)
}