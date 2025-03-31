rule Arbitrary_Code_Execution_in_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that execute arbitrary code during installation."
        confidence = 90
        severity = 80

    strings:
        $setup_function = "setup("
        $cmdclass_keyword = "cmdclass"
        $arbitrary_code = /[\w\s]*=\s*[\w\s]*\(\)/

    condition:
        all of them and
        $setup_function and
        $cmdclass_keyword and
        $arbitrary_code
}