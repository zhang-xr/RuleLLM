rule Token_Account_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects functions that manipulate token accounts, potentially for unauthorized transactions."
        confidence = 90
        severity = 85
    strings:
        $get_token_account = "get_token_account" wide
        $create_associated_token_account = "create_associated_token_account" wide
        $get_associated_token_address = "get_associated_token_address" wide
    condition:
        all of them
}