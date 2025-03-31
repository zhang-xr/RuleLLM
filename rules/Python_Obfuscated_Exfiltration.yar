rule Python_Obfuscated_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated Python scripts collecting system information and sending it via HTTP POST"
        confidence = 70
        severity = 60
    strings:
        $getuser_obf = /getpass\.[a-zA-Z0-9_]+\(\)/
        $getcwd_obf = /os\.[a-zA-Z0-9_]+\(\)/
        $gethostname_obf = /socket\.[a-zA-Z0-9_]+\(\)/
        $post_request_obf = /[a-zA-Z0-9_]+\.post\(.*\{.*\}.*\)/
    condition:
        all of ($getuser_obf, $getcwd_obf, $gethostname_obf) and $post_request_obf
}