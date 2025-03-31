rule Obfuscated_Clipboard_Stealer_JS {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated JavaScript code targeting clipboard operations"
        confidence = 90
        severity = 95
        
    strings:
        $hex_regex = /0x[0-9a-f]{4,6}/
        $obfuscated_var = /var _0x[0-9a-f]{4,6}=_0x[0-9a-f]{4,6};/
        $clipboard_ops = /clipboardWrite|clipboardRead|execCommand|copy|paste/
        $setinterval = "setInterval("
        
    condition:
        all of them and
        #hex_regex > 5 and
        #obfuscated_var > 3
}