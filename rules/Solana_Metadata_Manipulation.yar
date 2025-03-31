rule Solana_Metadata_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects parsing and manipulation of Solana metadata, potentially used for creating fraudulent tokens or NFTs."
        confidence = 90
        severity = 80
    strings:
        $metadata_structure = "instruction_structure = CStruct(\"instructionDiscriminator\" / U8, \"createMetadataAccountArgsV3\" / CStruct(\"data\" / CStruct(\"name\" / String, \"symbol\" / String, \"uri\" / String, \"sellerFeeBasisPoints\" / U16, \"creators\" / Option(Vec(CStruct(\"address\" / Bytes(32), \"verified\" / Bool, \"share\" / U8))), \"collection\" / Option(CStruct(\"verified\" / Bool, \"key\" / Bytes(32))), \"uses\" / Option(CStruct(\"useMethod\" / Enum(\"Burn\", \"Multiple\", \"Single\", enum_name=\"UseMethod\"), \"remaining\" / U64, \"total\" / U64)), \"isMutable\" / Bool, \"collectionDetails\" / Option(String))"
        $metadata_parsing = "metadata = instruction_structure.parse(decoded_info)"
        $metadata_conversion = "metadata = convert_bytes_to_pubkey(metadata)"
    condition:
        all of them
}