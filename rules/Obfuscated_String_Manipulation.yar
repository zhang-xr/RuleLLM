rule Obfuscated_String_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects Python code with obfuscated string manipulation patterns."
        confidence = 85
        severity = 75

    strings:
        $hex_string = /\\x[0-9a-f]{2}/
        $decode_call = /\.decode\(/
        $string_join = /\.join\('', \[/
        $dynamic_eval = /eval\(".*"\)/

    condition:
        any of them and
        filesize < 10KB and
        #hex_string > 5
}