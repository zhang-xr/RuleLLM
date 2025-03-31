rule Suspicious_Python_Setup_With_Exception {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python setup with empty exception handlers"
        confidence = "85"
        severity = "70"
    strings:
        $setup_function = "setup("
        $empty_exception = "except: pass"
        $author_esquelesquad = "author = 'EsqueleSquad'"
    condition:
        all of them
}