rule looks_for_the_combination_of_a_setup_function_with_unusual_or_suspicious_attributes {
    meta:
        description = "looks for the combination of a setup function with unusual or suspicious attributes"
        confidence = "85"
        severity = "80"

    strings:
        $setup_function = "setup("
        $author = "author = 'EsqueleSquad'"
        $email = "author_email = 'tahgoficial@proton.me'"
        $packages = "packages = ['modlib']"

    condition:
        all of them
}