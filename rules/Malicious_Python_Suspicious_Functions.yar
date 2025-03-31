rule Malicious_Python_Suspicious_Functions {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious function definitions in Python code."
        confidence = 80
        severity = 70

    strings:
        $long_func_name = /def\s+_{10,}\(.*\)/
        $eval_in_func = /eval\s*\(.*\)/
        $decode_in_func = /decode\s*\(.*\)/

    condition:
        $long_func_name and ($eval_in_func or $decode_in_func)
}