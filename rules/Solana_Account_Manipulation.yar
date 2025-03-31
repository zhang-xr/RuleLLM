rule Solana_Account_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects unusual account manipulation patterns in Solana interactions"
        confidence = 90
        severity = 80
    strings:
        $associated_token = "get_associated_token_address"
        $create_account = "create_associated_token_account"
        $token_account_opt = "TokenAccountOpts"
        $instruction_build = "SwapLayout.build"
    condition:
        all of ($associated_token, $create_account, $token_account_opt) and
        any of ($instruction_build)
}