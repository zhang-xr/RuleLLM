rule Solana_Token_Symbol_Fetching {
    meta:
        author = "RuleLLM"
        description = "Detects fetching of token symbols from an external API, potentially used for token manipulation or misrepresentation."
        confidence = 80
        severity = 70
    strings:
        $get_symbol_func = "def getSymbol(token):"
        $exclude_list = "exclude = ['EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB']"
        $api_url = "url = f\"https://api.dexscreener.com/latest/dex/tokens/{token}\""
        $response_check = "if response.status_code == 200:"
        $symbol_extraction = "Token_Symbol = pair['baseToken']['symbol']"
    condition:
        all of them
}