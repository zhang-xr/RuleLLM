from Generator import Generator
from Refiner import Refiner
from Fixer import Fixer
import json
import os
import re
import logging
import argparse

def process(input_file: str, output_dir: str, rule_type: str = "yara"):
    """
    Process malware clusters to generate and fix rules
    
    Args:
        input_file: Path to the clusters JSON file
        output_dir: Base directory for output files
        rule_type: Type of rules to generate ("yara" or "semgrep")
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Set file extension based on rule type
    rule_ext = ".yar" if rule_type == "yara" else ".yaml"

    # Set up logging
    log_file = os.path.join(output_dir, f"rulegen_{rule_type}.log")
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s %(name)s: %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    logging.info(f"Starting cluster processing - Input: {input_file}, Output: {output_dir}, Rule type: {rule_type}")

    # Initialize components
    generator = Generator()
    refiner = Refiner()
    fixer = Fixer()

    # Load clusters
    try:
        with open(input_file, 'r') as f:
            clusters = json.load(f)
        logging.info(f"Successfully loaded {len(clusters)} clusters from {input_file}")
    except Exception as e:
        logging.error(f"Failed to load clusters from {input_file}: {str(e)}")
        raise

    # Process each cluster
    for cluster in clusters:
        cluster_id = cluster['cluster_id']
        
        # Check if cluster has already been processed
        cluster_files = [f for f in os.listdir(output_dir) if f.startswith(f"cluster{cluster_id}_")]
        if cluster_files:
            logging.info(f"Skipping cluster {cluster_id} - output files already exist")
            continue
            
        logging.info(f"\n{'='*50}\nProcessing cluster {cluster_id} (size: {cluster['size']})")
        
        # Prepare samples based on cluster size
        if cluster['size'] <= 2:
            logging.info(f"Processing cluster {cluster_id} with single sample")
            samples = [
                {"code": cluster["all_members"][0]["code"]}
            ]
        else:
            logging.info(f"Processing cluster {cluster_id} with first two samples")
            samples = [
                {"code": cluster["all_members"][0]["code"]},
                {"code": cluster["all_members"][1]["code"]}
            ]
        
        # Generate rules
        logging.info(f"Generating {rule_type} rules for cluster {cluster_id}...")
        analysis = generator.generate_rules(samples, rule_type=rule_type)
        
        # Process through refiner and fixer
        rules = refiner.generate_rule_from_content(analysis, rule_type=rule_type)
        if rules:
            individual_rules = []
            # Split rules based on rule type
            if rule_type == "yara":
                for rule in rules:
                    split_rules = re.split(r'(?=rule\s+)', rule.strip())
                    individual_rules.extend([r.strip() for r in split_rules if r.strip()])
            else:
                # For Semgrep rules, split on rule pattern
                for rule in rules:
                    split_rules = re.split(r'(?=rules:\s*\n\s*-\s*id:|(?<!rules:)\s*-\s*id:)', rule.strip())
                    individual_rules.extend([r.strip() for r in split_rules if r.strip()])
                    
            for rule_idx, rule in enumerate(individual_rules, 1):
                fixed_rule, errors = fixer.fix_rule(rule, rule_type=rule_type)
                base_name = f"cluster{cluster_id}_{rule_idx}"
                if fixed_rule:
                    output_file = os.path.join(output_dir, f"{base_name}{rule_ext}")
                    with open(output_file, 'w') as f:
                        f.write(fixed_rule)
                else:
                    output_file = os.path.join(output_dir, f"{base_name}_invalid.txt")
                    with open(output_file, 'w') as f:
                        f.write(f"{rule}\n\nErrors:\n" + "\n".join(errors))

    logging.info(f"Completed processing all clusters with {rule_type} rules")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate and fix rules for malware clusters")
    parser.add_argument("--input", default="cluster/malware_clusters.json", help="Path to clusters JSON file")
    parser.add_argument("--output", default="output/rules", help="Base directory for output files")
    parser.add_argument("--rule-type", default="yara", choices=["yara", "semgrep"], help="Type of rules to generate")
    
    args = parser.parse_args()
    
    process(args.input, args.output, args.rule_type)



