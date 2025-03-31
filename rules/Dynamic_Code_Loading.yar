rule Dynamic_Code_Loading {
    meta:
        author = "RuleLLM"
        description = "Detects dynamic code loading using imports and execution"
        confidence = 88
        severity = 92
    strings:
        $import = "import" nocase
        $from = "from" nocase
        $exec = "exec" nocase
        $eval = "eval" nocase
        $base64 = "base64" nocase
        $zlib = "zlib" nocase
    condition:
        ($import and $from) and ($exec or $eval) and ($base64 or $zlib)
}