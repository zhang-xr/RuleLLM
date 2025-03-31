rule Fake_Pip_Package_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects fake pip package metadata combined with suspicious code patterns"
        confidence = 85
        severity = 80
    strings:
        $name = "name='PakePip'"
        $fake_url = "url='https://github.com/0x00-0x00/fakepip'"
        $fake_author = "author='HC2023'"
    condition:
        all of ($name, $fake_url, $fake_author)
}