rule Solana_Token_Account_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects manipulation of Solana token accounts, potentially used to steal or misappropriate tokens."
        confidence = 85
        severity = 75
    strings:
        $get_token_account = "def get_token_account(ctx, owner: Pubkey.from_string, mint: Pubkey.from_string):"
        $create_associated_token_account = "swap_token_account_Instructions = create_associated_token_account(owner, owner, mint)"
    condition:
        all of them
}