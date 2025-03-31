rule Benign_Utility_Functions {
    meta:
        description = "Detects benign utility functions for formatting, linting, and system analytics"
        author = "YARA Rule Expert"
        date = "2023-10-01"
        version = "1.0"
    
    strings:
        $analytics_function = /def\s+analytics\s*\(.*\)\s*:/
        $webhook_url = /webhook\.site/
        $system_info = /system\.platform|system\.version/
        $import_stack = /import\s+stack/
    
    condition:
        all of them
}