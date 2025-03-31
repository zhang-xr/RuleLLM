rule Python_Obfuscated_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using obfuscation techniques with eval/exec"
        confidence = "90"
        severity = "80"
    
    strings:
        $lambda = /_=lambda\s+\w+:/
        $eval = "eval"
        $exec = "exec"
        $chr_chain = /\".join\(chr\(i\) for i in \[/
        $base64 = /\bbase64\.b64decode\(/
    
    condition:
        any of ($lambda, $eval, $exec) and 
        (1 of ($chr_chain, $base64))
}