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

Required dependencies include:
- openai
- yara-python
- semgrep
- torch
- transformers
- scikit-learn
- numpy
- tqdm

## Configuration

Create a `config.ini` file in the project root:
```ini
[Settings]
Model = <model-name>        # e.g., gpt-4-0125-preview
ModelApiKey = <your-api-key> # Your API key
BaseURL = <api-base-url>     # API base URL, such as https://api.openai.com/v1
```

## Workflow

The system employs a three-phase process to generate effective malware detection rules:

1. **Clustering & Preprocessing**:
   - Uses `cluster_malware.py` to analyze and cluster similar malware samples
   - Leverages CodeBERT to generate embeddings for code samples
   - Applies K-means clustering to group similar malware
   - Filters large and heavily encoded samples to improve processing efficiency

2. **Rule Generation Process**:
   - Selects samples from each cluster
   - `Generator` analyzes samples and creates initial rules
   - `Refiner` optimizes rules to improve detection efficiency and reduce false positives
   - `Fixer` validates rule format and fixes any syntax errors

3. **Output & Logging**:
   - Generates separate rule files for each cluster
   - Records processing progress and validation results
   - Marks and stores invalid rule information for further analysis

## Usage

### Malware Clustering

```bash
python -m rulegen.cluster_malware --base_path /path/to/malware/samples --output_path /path/to/clusters
```

Parameters:
- `--base_path`: Directory path containing malware samples
- `--output_path`: Directory for clustering output

### Rule Generation

```bash
python -m rulegen.run --input /path/to/clusters.json --output /path/to/output --rule-type yara
```

Parameters:
- `--input`: Path to the JSON file containing malware clusters (default: "cluster/malware_clusters.json")
- `--output`: Directory for generated rules (default: "output/rules")
- `--rule-type`: Type of rules to generate ("yara" or "semgrep", default: "yara")

## Project Structure

- `rulegen/`: Main source code directory
  - `Generator.py`: Analyzes malicious code samples and generates initial rules
  - `Refiner.py`: Optimizes and improves generated rules
  - `Fixer.py`: Validates and fixes syntax errors in rules
  - `client.py`: Communication interface with language model API
  - `cluster_malware.py`: Analysis and clustering of malware samples
  - `run.py`: Main execution script, coordinates workflow

## Components in Detail

### Clustering Engine
- Uses CodeBERT model to generate code embeddings
- Applies KMeans clustering to identify similar malware
- Calculates similarity between samples using cosine similarity
- Filters large and heavily encoded samples
- Uses PCA for dimensionality reduction

### Generator
- Analyzes malware sample characteristics
- Generates initial detection rules
- Handles code segmentation and analysis
- Intelligently processes complex and multi-part code
- Creates independent rules for each sample

### Refiner
- Improves rule quality and detection efficiency
- Extracts common malicious behavior patterns
- Optimizes rule structure to reduce false positives
- Enhances readability through unified rule formatting
- Creates rules based on behavioral features rather than static features

### Fixer
- Validates generated rule formats
- Fixes compilation and syntax errors
- Ensures rule compatibility and effectiveness
- Provides detailed error reports
- Supports multiple fix attempts for complex errors

## Output

The system generates:
- Individual rule files for each cluster
- Validation logs
- Error reports for invalid rules
- Progress tracking information
- Clustering results and analysis data

## Logging

Detailed logs are generated in the output directory:
- Generation process logs
- Validation results
- Error messages and debugging information
- Rule generation performance metrics

## Requirements

- Python 3.7+
- CUDA support (recommended for clustering)
- YARA-python (for YARA rule validation)
- Semgrep (for Semgrep rule validation)
- OpenAI API access or compatible API
- Sufficient storage space for samples and results

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details 
