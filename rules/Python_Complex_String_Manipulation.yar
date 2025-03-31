rule Python_Complex_String_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects complex string manipulation patterns in Python code"
        confidence = 85
        severity = 80
        
    strings:
        $complex_string = /[^\x00-\x7F]{20,}/
        $join_call = ".join("
        $chr_call = "chr("
        $int_call = "int("
        $eval_call = "eval("
        
    condition:
        all of ($join_call, $chr_call, $int_call) and 
        any of ($complex_string, $eval_call)
}