rule Solana_AMM_Configuration {
    meta:
        author = "RuleLLM"
        description = "Detects configuration of a Solana AMM, potentially used for manipulating liquidity pools or executing malicious trades."
        confidence = 80
        severity = 70
    strings:
        $amm_layout = "AMM_INFO_LAYOUT_V4_1 = cStruct(\"status\" / Int64ul, \"nonce\" / Int64ul, \"orderNum\" / Int64ul, \"depth\" / Int64ul, \"coinDecimals\" / Int64ul, \"pcDecimals\" / Int64ul, \"state\" / Int64ul, \"resetFlag\" / Int64ul, \"minSize\" / Int64ul, \"volMaxCutRatio\" / Int64ul, \"amountWaveRatio\" / Int64ul, \"coinLotSize\" / Int64ul, \"pcLotSize\" / Int64ul, \"minPriceMultiplier\" / Int64ul, \"maxPriceMultiplier\" / Int64ul, \"systemDecimalsValue\" / Int64ul, \"minSeparateNumerator\" / Int64ul, \"minSeparateDenominator\" / Int64ul, \"tradeFeeNumerator\" / Int64ul, \"tradeFeeDenominator\" / Int64ul, \"pnlNumerator\" / Int64ul, \"pnlDenominator\" / Int64ul, \"swapFeeNumerator\" / Int64ul, \"swapFeeDenominator\" / Int64ul, \"needTakePnlCoin\" / Int64ul, \"needTakePnlPc\" / Int64ul, \"totalPnlPc\" / Int64ul, \"totalPnlCoin\" / Int64ul, \"poolOpenTime\" / Int64ul, \"punishPcAmount\" / Int64ul, \"punishCoinAmount\" / Int64ul, \"orderbookToInitTime\" / Int64ul, \"swapCoinInAmount\" / BytesInteger(16, signed=False, swapped=True), \"swapPcOutAmount\" / BytesInteger(16, signed=False, swapped=True), \"swapCoin2PcFee\" / Int64ul, \"swapPcInAmount\" / BytesInteger(16, signed=False, swapped=True), \"swapCoinOutAmount\" / BytesInteger(16, signed=False, swapped=True), \"swapPc2CoinFee\" / Int64ul, \"poolCoinTokenAccount\" / Bytes(32), \"poolPcTokenAccount\" / Bytes(32), \"coinMintAddress\" / Bytes(32), \"pcMintAddress\" / Bytes(32), \"lpMintAddress\" / Bytes(32), \"ammOpenOrders\" / Bytes(32), \"serumMarket\" / Bytes(32), \"serumProgramId\" / Bytes(32), \"ammTargetOrders\" / Bytes(32), \"poolWithdrawQueue\" / Bytes(32), \"poolTempLpTokenAccount\" / Bytes(32), \"ammOwner\" / Bytes(32), \"pnlOwner\" / Bytes(32))"
        $amm_program_id = "AMM_PROGRAM_ID = Pubkey.from_string('675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8')"
    condition:
        all of them
}