rule Malicious_Python_Setup_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated code execution in Python setup scripts"
        confidence = 90
        severity = 80

    strings:
        $custom_install = "class CustomInstallCommand(install):"
        $eval_compile = "eval(compile("
        $xor_decryption = /chr\(ord\([^)]+\) \^ ord\([^)]+\)\)/
        $long_obfuscated_string = /[\x00-\x1F\x7F-\xFF]{50,}/

    condition:
        all of them
}