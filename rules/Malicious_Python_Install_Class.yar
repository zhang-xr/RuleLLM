rule Malicious_Python_Install_Class {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python install class for data collection"
        confidence = 95
        severity = 90
    strings:
        $s1 = "class CustomInstall(install)"
        $s2 = /'p': \w+,\s+'h': \w+,\s+'d': \w+,\s+'c': \w+/
        $s3 = "json.dumps(data)"
        $s4 = "encode('utf-8').hex()"
    condition:
        all of them
}