rule Suspicious_PipPackage_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious metadata in a pip package setup script."
        confidence = 75
        severity = 80

    strings:
        $description = "description='This will exploit a sudoer able to /usr/bin/pip install *'"
        $url = "url='https://github.com/0x00-0x00/fakepip'"
        $name = "name='QakePip'"

    condition:
        all of them and filesize < 10KB
}