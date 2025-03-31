rule Solana_Suspicious_Token_Symbol_Fetching {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious token symbol fetching using external API requests"
        confidence = 85
        severity = 75
    strings:
        $api_url = "https://api.dexscreener.com/latest/dex/tokens/"
        $token_symbol_fetch = "getSymbol(token)"
        $http_request = "requests.get(url)"
        $exclude_tokens = "exclude = ['EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB']"
    condition:
        all of ($api_url, $token_symbol_fetch, $http_request) and
        any of ($exclude_tokens)
}