rule Suspicious_Roblox_Related_Package {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python packages targeting Roblox"
        confidence = 85
        severity = 75
    strings:
        $roblox_lib = "robloxpy"
        $http_lib = "requests"
    condition:
        all of them
}