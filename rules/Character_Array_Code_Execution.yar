rule Character_Array_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious character array patterns used for code execution"
        confidence = 90
        severity = 85
        
    strings:
        $char_array = /\[(\d{2,3},){3,}\d{2,3}\]/
        $exec_pattern = /exec\s*\(/
        $eval_pattern = /eval\s*\(/
        $chr_pattern = /chr\s*\(int\s*\(/
        
    condition:
        $char_array and ($exec_pattern or $eval_pattern) and $chr_pattern
}