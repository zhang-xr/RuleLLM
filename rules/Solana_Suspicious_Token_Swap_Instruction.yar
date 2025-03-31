rule Solana_Suspicious_Token_Swap_Instruction {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious token swap instructions in Solana blockchain interactions"
        confidence = 85
        severity = 75
    strings:
        $swap_instruction = "SwapLayout = cStruct("
        $instruction_9 = "instruction=9"
        $token_account = "token_account_in"
        $min_amount_zero = "min_amount_out=0"
    condition:
        all of them and
        filesize < 50KB
}