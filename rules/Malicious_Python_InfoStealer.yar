rule Malicious_Python_InfoStealer {
    meta:
        author = "RuleLLM"
        description = "Detects Python-based information stealer collecting system data and exfiltrating via HTTP"
        confidence = 90
        severity = 85
    strings:
        $getmac = /subprocess\.check_output\(["']getmac["'], shell=True\)/ nocase
        $ifconfig = /subprocess\.check_output\(["']ifconfig["'], shell=True\)/ nocase
        $platform = /platform\.node\(\)/ nocase
        $getuser = /getpass\.getuser\(\)/ nocase
        $b64encode = /base64\.b64encode\(.*\.encode\(['"]utf-8['"]\)\)/ nocase
        $urlopen = /urllib\.request\.urlopen\(.*\)/ nocase
        $error_suppress = /except Exception as e:\s*pass/ nocase
    condition:
        4 of them and filesize < 10KB
}