rule Malicious_Python_Builtins_Modification {
    meta:
        author = "RuleLLM"
        description = "Detects Python code modifying __builtins__ using setattr."
        confidence = "85"
        severity = "90"

    strings:
        $setattr = "setattr"
        $builtins = "__builtins__"
        $eval = "eval"
        $exec = "exec"

    condition:
        all of ($setattr, $builtins) and 
        any of ($eval, $exec)
}