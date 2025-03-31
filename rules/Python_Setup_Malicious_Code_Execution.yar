rule Python_Setup_Malicious_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious code execution patterns in Python setup scripts"
        confidence = 85
        severity = 85

    strings:
        $setup_import = "from setuptools import setup, find_packages"
        $custom_install = "class CustomInstallCommand(install):"
        $eval_compile = "eval(compile("
        $xor_decryption = /chr\(ord\([^)]+\) \^ ord\([^)]+\)\)/

    condition:
        $setup_import and $custom_install and ($eval_compile or $xor_decryption)
}