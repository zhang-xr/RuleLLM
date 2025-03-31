rule Monero_Miner_Script_Download {
    meta:
        author = "RuleLLM"
        description = "Detects download of Monero mining script in Python code"
        confidence = 95
        severity = 95
    strings:
        $monero_script = "setup_moneroocean_miner.sh"
        $github_raw = "raw.githubusercontent.com"
        $curl = /curl\s+-\s*[sL]\s+/
        $bash = /bash\s+-\s*s\s+/
    condition:
        $monero_script and $github_raw and ($curl or $bash)
}