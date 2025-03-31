rule Python_Base64_CodeInjection {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoded code injection patterns"
        confidence = 90
        severity = 85
    strings:
        $base64 = "base64.b64decode("
        $exec = "exec("
        $compile = "compile("
    condition:
        all of them
}