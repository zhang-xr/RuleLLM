rule Python_Suspicious_DataCollection {
    meta:
        author = "RuleLLM"
        description = "Detects Python code collecting sensitive system information"
        confidence = 90
        severity = 75
    strings:
        $system_info = /(getuser|getcwd|gethostname)\(\)/
        $network_ops = /(requests\.(post|get)|urllib|httplib)/
        $json_usage = /\.json\s*=\s*\{/
    condition:
        all of them
}