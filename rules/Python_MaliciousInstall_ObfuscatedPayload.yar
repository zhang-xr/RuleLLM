rule Python_MaliciousInstall_ObfuscatedPayload {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated code execution in Python setup scripts"
        confidence = "95"
        severity = "90"
    
    strings:
        $install_class = "class CustomInstallCommand(install):"
        $eval_compile = "eval(compile("
        $xor_loop = /for [a-zA-Z0-9_]+ in range\([a-zA-Z0-9_]+\):/
        $chr_ord = /chr\(ord\([a-zA-Z0-9_]+\) [\^&|] ord\([a-zA-Z0-9_]+\)\)/
        $long_hex = /\\x[0-9a-f]{2}/
    
    condition:
        all of ($install_class, $eval_compile) and 
        (1 of ($xor_loop, $chr_ord) or 
        $long_hex in (0..1000))
}