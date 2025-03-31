rule Suspicious_Builtin_Modification {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to modify built-in functions attributes"
        confidence = 95
        severity = 90
        
    strings:
        $setattr_pattern = /setattr\s*\(__builtins__/
        $builtins_ref = /__builtins__/
        $exec_ref = /exec\s*\(/
        $eval_ref = /eval\s*\(/
        
    condition:
        $setattr_pattern and ($builtins_ref or $exec_ref or $eval_ref)
}