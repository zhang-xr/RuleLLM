import time
import logging
from typing import List, Dict
from client import LLMClient

class Generator:
    def __init__(self):
        """
        Initializes the malware rule generator with OpenAI client and logging configuration.
        """
        self.client = LLMClient()
        self.logger = logging.getLogger(__name__)
        self.prompts = {
            "yara": """As a malware analysis expert, analyze this code segment and generate one or more precise YARA rules to detect malicious patterns. Generate multiple rules if it would improve detection accuracy and reduce false positives.
            
            [Previous analysis summary: {prev_analysis}]
            
            {code}
            
            Required to answer:
            
            1. Malicious Pattern Identification:
            - Identify suspicious code patterns with high confidence
              * Extract exact code snippet with context
              * Explain malicious behavior and impact
              
            2. Generate rules based on:
              * Sample complexity and feature distribution
              * Independence of different malicious behavior patterns
              * Variant detection coverage requirements
              * Need for false positive control
            - Ensure rules complement each other for comprehensive detection coverage
            - Each rule should focus on specific malicious behavior patterns
            - Minimize false positives while maintaining detection effectiveness
            
            Each rule must be wrapped with ```yara and ```:
            rule [descriptive_name] {{
                meta:
                    "author" = "RuleLLM"
                    "description" = "Detailed behavior description"
                    "confidence" = "1-100"
                    "severity" = "1-100"
                    
                strings:
                    // Include multiple detection patterns:
                    // - Exact suspicious strings
                    // - Regex for common variations
                    // - Byte patterns for binary indicators
                    // - Context-aware wildcards
                    
                condition:
                    // Combine patterns logically to:
                    // - Detect core malicious behavior
                    // - Account for known variants
                    // - Exclude benign matches
                    // - Use proximity/ordering where relevant
            }}
            
            Focus on creating rules that:
            1. Target malicious behaviors
            2. Handle common obfuscation techniques
            3. Avoid matching legitimate code patterns
            
            Provide detailed justification for each rule component.""",
            
            "semgrep": """As a security analysis expert, analyze this code segment and generate precise Semgrep rules to detect vulnerable or malicious patterns. Generate multiple rules if it would improve detection accuracy and reduce false positives.
            
            [Previous analysis summary: {prev_analysis}]
            
            {code}
            
            Required to answer:
            
            1. Security Issue Identification:
            - Identify suspicious/vulnerable code patterns with high confidence
              * Extract exact code snippet with context
              * Explain security risks and potential impact
              
            2. Generate Semgrep rules based on:
              * Code language and structure
              * Specific vulnerability patterns identified
              * Common vulnerability variations
              * Need for false positive control
            - Each rule should focus on a specific security issue
            - Ensure rules are language-appropriate for the analyzed code
            - Minimize false positives while maintaining detection effectiveness
            
            Each rule must be wrapped with ```yaml and ```:
            ```yaml
            rules:
            - id: rule-unique-id
              pattern: |
                # Pattern using Semgrep syntax to match the vulnerable code
                # Include variables with metavariables as needed
              message: "Clear description of the security issue detected"
              metadata:
                author: "RuleLLM"
                description: "Detailed explanation of the vulnerability"
                confidence: "high/medium/low"
                severity: "critical/high/medium/low/info"
                references:
                  - "URL or reference to similar vulnerabilities if applicable"
              languages: [language_name]  # Specify the target language(s)
              severity: ERROR/WARNING/INFO
            ```
            
            Focus on creating rules that:
            1. Target specific security vulnerabilities (like injection, authentication bypass, etc.)
            2. Detect insecure coding patterns
            3. Recognize potentially malicious behavior
            4. Avoid matching legitimate code patterns
            
            Use appropriate Semgrep pattern syntax including:
            - Abstract syntax tree (AST) pattern matching
            - Metavariables (e.g., $X, $Y) to track variables
            - Ellipsis (...) for indicating arbitrary code gaps
            - Pattern-either and pattern-not for complex matches
            
            Provide detailed justification for each rule component."""
        }

    def generate_rules(self, samples: List[Dict], rule_type: str = "yara") -> str:
        """
        Analyzes multiple malware samples from the same cluster and generates rules.
        
        Args:
            samples (List[Dict]): List of dictionaries containing malware code samples
            rule_type (str): Type of rules to generate ("yara" for YARA rules, "semgrep" for Semgrep rules)
            
        Returns:
            str: Combined analysis results and rules for all samples
        """
        if rule_type not in self.prompts:
            raise ValueError(f"Invalid rule_type: {rule_type}. Must be one of {list(self.prompts.keys())}")
            
        max_retries = 3
        retry_count = 0
        base_wait_time = 3
        segment_size = 8000  # Maximum size for each code segment
        
        while retry_count < max_retries:
            try:
                combined_analysis = []
                
                for idx, sample in enumerate(samples, 1):
                    code = sample['code']
                    lines = code.split('\n')
                    
                    code_segments = []
                    current_segment = []
                    current_size = 0
                    current_depth = 0
                    
                    def is_block_start(line: str) -> bool:
                        stripped = line.strip()
                        return (stripped.startswith(('def ', 'class ', 'if ', 'for ', 'while ', 'try:', 'with ')) 
                                or stripped.endswith(':'))
                    
                    def is_block_end(line: str, prev_indent: int, current_indent: int) -> bool:
                        return current_indent < prev_indent
                    
                    prev_indent = 0
                    for line in lines:
                        current_indent = len(line) - len(line.lstrip())
                        line_length = len(line)
                        
                        if is_block_start(line):
                            current_depth += 1
                        elif is_block_end(line, prev_indent, current_indent):
                            current_depth = max(0, current_depth - 1)
                        
                        if current_size + line_length > segment_size and current_depth == 0:
                            if current_segment:
                                code_segments.append('\n'.join(current_segment))
                                current_segment = []
                                current_size = 0
                        
                        current_segment.append(line)
                        current_size += line_length
                        prev_indent = current_indent
                    
                    if current_segment:
                        code_segments.append('\n'.join(current_segment))
                    # self.logger.info(f"Code segments for Sample {idx}:\n{code_segments}\n")
                    
                    # Skip if too many segments (likely obfuscated/encoded code)
                    if len(code_segments) > 3:
                        self.logger.warning(f"Sample {idx} has {len(code_segments)} segments, likely obfuscated/encoded. Skipping analysis.")
                        combined_analysis.append(f"\nAnalysis for Sample {idx}:\nSkipped - Sample appears to be heavily obfuscated or encoded (split into {len(code_segments)} segments)")
                        continue
                    
                    # Process each code segment separately
                    segment_analyses = []
                    for segment_idx, segment in enumerate(code_segments, 1):
                        prompt = self.prompts[rule_type].format(
                            code=segment,
                            prev_analysis=' | '.join(segment_analyses) if segment_analyses else 'None'
                        )
                        
                        try:
                            response = self.client.invoke(
                                messages=[
                                    {"role": "system", "content": prompt},
                                ]
                            )
                            segment_analyses.append(response)
                            
                        except Exception as api_error:
                            self.logger.warning(f"API error for sample {idx}, segment {segment_idx}: {str(api_error)}. Retrying...")
                            time.sleep(base_wait_time)
                            continue
                    
                    # Combine all segment analyses
                    combined_segment_analysis = f"\nAnalysis for Sample {idx}:\n" + "\n".join(segment_analyses)
                    combined_analysis.append(combined_segment_analysis)
                self.logger.info(f"Combined analysis:\n{combined_analysis}")
                return "\n".join(combined_analysis)

            except Exception as e:
                retry_count += 1
                if retry_count == max_retries:
                    self.logger.error(f"Maximum retries reached. Last error: {str(e)}")
                    raise
                wait_time = base_wait_time * (2 ** retry_count)
                self.logger.warning(f"Error occurred, retrying in {wait_time} seconds... Error: {str(e)}")
                time.sleep(wait_time)

