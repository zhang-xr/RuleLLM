rule Obfuscated_Strings_In_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated strings in Python setup scripts"
        confidence = 85
        severity = 70

    strings:
        $long_description = /DESCRIPTION\s*=\s*'[A-Za-z0-9\s]{50,}'/
        $long_description_content = /LONG_DESCRIPTION\s*=\s*'[A-Za-z0-9\s]{100,}'/

    condition:
        any of them
}