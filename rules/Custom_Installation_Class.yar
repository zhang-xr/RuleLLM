rule Custom_Installation_Class {
    meta:
        author = "RuleLLM"
        description = "Detects custom installation class in Python setup scripts"
        confidence = 85
        severity = 75

    strings:
        $install_class = "class install(_install):"
        $cmdclass = "'install': install"

    condition:
        all of them
}