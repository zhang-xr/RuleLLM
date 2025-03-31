rule Python_Package_InfoStealer {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package setup with potential info-stealing code"
        confidence = 80
        severity = 85
    strings:
        $s1 = /setuptools\.setup\(/
        $s2 = /install_requires=\[\]/
        $s3 = /long_description=open\('README\.md'\)\.read\(\)/
    condition:
        all of ($s*) and any of them in (0..500)
}