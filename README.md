# Malware Detection Rule Generator

A Python-based tool that automatically generates, refines, and validates malware detection rules from code samples. The system supports both YARA and Semgrep rule generation, using advanced language models to analyze malicious code patterns.

## Features

- **Automated Rule Generation**: Analyzes malicious code samples to generate detection rules
- **Multiple Rule Types**: Supports both YARA and Semgrep rule formats
- **Intelligent Clustering**: Groups similar malware samples for more effective rule generation
- **Rule Refinement**: Improves initial rules through pattern analysis and optimization
- **Validation System**: Automatically validates and fixes generated rules
- **Progress Tracking**: Maintains detailed logs of the generation process

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd malware-rule-generator
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Create a `config.ini` file in the project root:
```ini
[Settings]
Model = <model-name>
ModelApiKey = <your-api-key>
BaseURL = <api-base-url>
```

## Usage

Run the main script with custom parameters:
```bash
python run.py --input /path/to/clusters.json --output /path/to/output --rule-type yara
```

Arguments:
- `--input`: Path to the JSON file containing malware clusters (default: "cluster/malware_clusters.json")
- `--output`: Directory for generated rules (default: "output/rules")
- `--rule-type`: Type of rules to generate ("yara" or "semgrep", default: "yara")

## Project Structure

- `Generator.py`: Main rule generation logic
- `Refiner.py`: Rule refinement and optimization
- `Fixer.py`: Rule validation and fixing
- `client.py`: API client implementation
- `run.py`: Main execution script

## Components

### Generator
- Analyzes malware samples
- Generates initial detection rules
- Handles code segmentation and analysis

### Refiner
- Improves rule quality
- Extracts common patterns
- Optimizes rule structure

### Fixer
- Validates generated rules
- Fixes common rule issues
- Ensures rule compatibility

## Output

The system generates:
- Individual rule files for each cluster
- Validation logs
- Error reports for invalid rules
- Progress tracking information

## Logging

Detailed logs are generated in the output directory:
- Generation process logs
- Validation results
- Error messages and debugging information

## Requirements

- Python 3.7+
- YARA-python (for YARA rule validation)
- Semgrep (for Semgrep rule validation)
- OpenAI API access
- Required Python packages (see requirements.txt)

## License

[Specify your license here]

## Contributing

[Add contribution guidelines if applicable]
