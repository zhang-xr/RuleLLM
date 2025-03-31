rule Solana_Hardcoded_Program_IDs {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded Solana program IDs commonly used in malicious contracts."
        confidence = 85
        severity = 75
    strings:
        $amm_program_id = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
        $serum_program_id = "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX"
    condition:
        any of them
}