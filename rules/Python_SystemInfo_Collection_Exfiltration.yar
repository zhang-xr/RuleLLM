rule Python_SystemInfo_Collection_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code collecting system information and exfiltrating via HTTP POST"
        confidence = 90
        severity = 80
    strings:
        $hostname = "subprocess.check_output(['hostname'])" nocase
        $username = "os.getlogin()" nocase
        $dirname = "os.path.basename(os.getcwd())" nocase
        $http_post = "requests.post(" nocase
        $json_data = "json=data" nocase
    condition:
        all of them
}