rule Solana_Complex_Struct_Definitions {
    meta:
        author = "RuleLLM"
        description = "Detects complex struct definitions that could be used for exploits"
        confidence = 85
        severity = 75
    strings:
        $amm_layout = "AMM_INFO_LAYOUT_V4_1 = cStruct("
        $market_layout = "MARKET_LAYOUT = cStruct("
        $pool_layout = "POOL_INFO_LAYOUT = cStruct("
    condition:
        any of ($amm_layout, $market_layout, $pool_layout)
}