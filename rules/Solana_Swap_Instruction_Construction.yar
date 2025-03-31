rule Solana_Swap_Instruction_Construction {
    meta:
        author = "RuleLLM"
        description = "Detects construction of a Solana swap instruction, potentially used for malicious token swaps or fund draining."
        confidence = 85
        severity = 75
    strings:
        $swap_layout = "SwapLayout = cStruct(\"instruction\" / Int8ul, \"amount_in\" / Int64ul, \"min_amount_out\" / Int64ul)"
        $make_swap_instruction = "def make_swap_instruction(amount_in: int, token_account_in: Pubkey.from_string, token_account_out: Pubkey.from_string, accounts: dict, mint, ctx, owner) -> Instruction:"
        $swap_keys = "keys = ["
        $swap_data = "data = SwapLayout.build(dict(instruction=9, amount_in=int(amount_in), min_amount_out=0"
    condition:
        all of them
}