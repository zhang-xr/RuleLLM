rule Malicious_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects code execution patterns using eval and exec"
        confidence = 90
        severity = 95
    strings:
        $eval = "eval" nocase
        $exec = "exec" nocase
        $chr_array = /chr\(\d+\)/
        $join = "join"
        $base64 = "base64"
        $zlib = "zlib"
        $codecs = "codecs"
    condition:
        ($eval or $exec) and $chr_array and $join and ($base64 or $zlib or $codecs)
}