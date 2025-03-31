rule Suspicious_Analytics_Function {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious analytics function that collects and sends system data"
        confidence = 75
        severity = 65
        
    strings:
        $analytics_function = "def analytics():"
        $system_info_collection = /(platform|psutil|socket)\.\w+\(\)/
        $data_dict = /\{\s*['\"]os['\"]\s*:/
        $webhook_post = /requests\.post\(["'][^"]+["'],\s*json=/
        
    condition:
        $analytics_function and 
        3 of ($system_info_collection) and 
        $data_dict and 
        $webhook_post
}