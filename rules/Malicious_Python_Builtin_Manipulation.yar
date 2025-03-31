rule Malicious_Python_Builtin_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to manipulate Python built-in functions"
        confidence = 95
        severity = 90

    strings:
        $setattr_pattern = /setattr\s*\(\s*__builtins__\s*,/
        $exec_pattern = /exec\s*\(.*\)/
        $eval_pattern = /eval\s*\(.*\)/

    condition:
        $setattr_pattern and 
        any of ($exec_pattern, $eval_pattern)
}