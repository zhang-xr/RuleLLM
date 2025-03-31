rule Dynamic_Package_Metadata_Retrieval {
    meta:
        author = "RuleLLM"
        description = "Detects dynamic retrieval of package metadata, which could be used to identify malicious context"
        confidence = 70
        severity = 50
    strings:
        $package_metadata = "importlib.metadata.metadata"
        $current_package = "__name__.split('.')[0]"
    condition:
        $package_metadata and $current_package
}