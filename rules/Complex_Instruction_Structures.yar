rule Complex_Instruction_Structures {
    meta:
        author = "RuleLLM"
        description = "Detects complex instruction structures often used in malicious Solana transactions."
        confidence = 80
        severity = 70
    strings:
        $instruction_structure = "instructionDiscriminator" wide
        $metadata_structure = "createMetadataAccountArgsV3" wide
        $swap_layout = "SwapLayout" wide
    condition:
        all of them
}