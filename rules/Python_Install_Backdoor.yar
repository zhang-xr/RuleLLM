rule Python_Install_Backdoor {
    meta:
        author = "RuleLLM"
        description = "Detects Python package installation backdoor using XOR decoding and eval"
        confidence = "90"
        severity = "95"
    strings:
        $xor_decode = /[\w\d]+ = \"[^\"]+\"[\s\S]+for [\w\d]+ in range\(len\([\w\d]+\)\):[\s\S]+chr\(ord\([\w\d]+\[[\w\d]+\]\) \^ [^\n]+\)/
        $custom_install = "class CustomInstallCommand(install)"
        $eval_compile = "eval(compile("
        $setup_py = "from setuptools import setup"
    condition:
        all of them
}