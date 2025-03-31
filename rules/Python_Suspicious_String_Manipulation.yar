rule Python_Suspicious_String_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious string manipulation patterns"
        confidence = 80
        severity = 75
    strings:
        $s1 = /replace\('\\n',''\)\)\)\)/
        $s2 = /"".join\(chr\(int\(int\(.*split\(\)\[.*\]\)\/random\.randint\(1,\d+\)\)\)/
        $s3 = /f'\x5f\x5f\x5f\x5f\x28.*\x5d\x29\x29\(/
        $s4 = /why,are,you,reading,this,thing,huh=/
    condition:
        2 of them
}