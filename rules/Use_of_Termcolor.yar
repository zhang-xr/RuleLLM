rule Use_of_Termcolor {
    meta:
        author = "RuleLLM"
        description = "Detects use of termcolor library in malicious scripts"
        confidence = 65
        severity = 70
    strings:
        $termcolor_import = "import termcolor"
        $termcolor_colored = "termcolor.colored"
    condition:
        all of them
}