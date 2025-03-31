rule Python_MaliciousPackage_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package setup with obfuscated code execution"
        confidence = 95
        severity = 90
        reference = "Custom package installation with eval/compile execution"
    
    strings:
        $setup_import = "from setuptools import setup, find_packages"
        $custom_install = "class CustomInstallCommand(install)"
        $eval_compile = "eval(compile("
        $xor_pattern = /chr\(ord\([a-zA-Z0-9_]+\) \^ ord\([a-zA-Z0-9_]+\)\)/
        $long_hex = /\\x[0-9a-f]{2}/
        $suspicious_var = /\b[a-zA-Z]{10,}\b/  // Matches long random-looking variable names
        
    condition:
        all of them and 
        filesize < 50KB and 
        #long_hex > 50 and 
        #suspicious_var > 5
}