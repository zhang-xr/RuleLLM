rule Python_Suspicious_String_Operations {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious string manipulation patterns in Python code"
        confidence = "85"
        severity = "75"
    
    strings:
        $hex_str = /\\x[0-9a-f]{2}/
        $join_op = /\.join\(/
        $chr_func = /chr\(int\(/
        $complex_str = /\"\"\.join\(chr\(int\(/
    
    condition:
        2 of ($hex_str, $join_op, $chr_func) and
        $complex_str
}