rule EvilPackage_Domain_Reference {
    meta:
        author = "RuleLLM"
        description = "Detects references to the suspicious domain evilpackage.fatezero.org"
        confidence = "95"
        severity = "85"
    
    strings:
        $domain1 = "http://evilpackage.fatezero.org/" ascii wide
        $domain2 = "evilpackage.fatezero.org" ascii wide
    
    condition:
        any of them
}