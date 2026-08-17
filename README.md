# CyberGuard - Cybersecurity Domain-Specific Language

A command-line domain-specific language (DSL) for cybersecurity that enables security engineers and developers to express security intent in a simple, declarative syntax and execute security specifications from the command line.

## 🎯 Overview

CyberGuard is designed to streamline security testing and validation by providing a high-level, human-readable DSL that abstracts away the complexity of security testing frameworks.

### Supported Domains

1. **PenTesting & Application Security (AppSec)**
   - API security testing
   - Authentication & authorization validation
   - Input validation and injection testing
   - Session management verification

2. **Cloud Security**
   - AWS security configuration validation
   - Azure security posture assessment
   - IAM and access control verification
   - Storage and encryption compliance checking

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/karthiga117/PSE-CyberGuard.git
cd PSE-CyberGuard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the project
pip install -e .

# Install development dependencies
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Display version
cyberguard --version

# Display help
cyberguard --help

# Execute a DSL file (Phase 2+)
cyberguard run examples/authentication.cg
```

## 📋 Project Status

### Phase 1: Project Foundation ✅
- Python project setup with pyproject.toml
- CLI skeleton with Typer
- Basic command structure (`--version`, `--help`, `run`)
- Test infrastructure
- Documentation

### Phase 2: Language Design & Specification (Planned)
- DSL grammar and syntax specification
- Lexer implementation
- Parser implementation
- Abstract Syntax Tree (AST) design

### Phase 3: Core Engine (Planned)
- AST interpreter
- Execution framework
- Security rule engine
- Reporting system

### Phase 4: AppSec Engine (Planned)
- HTTP/REST client
- Authentication testing
- Vulnerability scanning
- Security assertion validation

### Phase 5: Cloud Engine (Planned)
- AWS integration
- Azure integration
- GCP integration
- Cloud security validation

## 📂 Project Structure

```
CyberGuard/
├── cyberguard/              # Main package
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── language/           # DSL language (Phase 2+)
│   ├── engine/             # Core execution engine (Phase 3+)
│   ├── appsec/             # AppSec domain engine (Phase 4+)
│   ├── cloud/              # Cloud security engine (Phase 5+)
│   ├── rules/              # Security rules (Phase 4+)
│   └── reporting/          # Report generation (Phase 3+)
├── examples/               # Example DSL files
├── tests/                  # Test suite
├── README.md               # This file
├── .gitignore              # Git ignore rules
├── pyproject.toml          # Project configuration
└── LICENSE                 # MIT License
```

## 🛠️ Development

### Running Tests

```bash
pytest                     # Run all tests
pytest -v                  # Verbose output
pytest --cov              # With coverage
```

### Code Quality

```bash
black .                    # Format code
ruff check .              # Lint code
mypy cyberguard           # Type checking
```

## 📝 Example DSL (Future)

### PenTesting Example

```cyberguard
target web "http://localhost:5000"

test "Authentication":
    request GET "/api/profile"
    expect status 401

test "JWT Token Validation":
    request GET "/api/admin" with headers {"Authorization": "Bearer invalid_token"}
    expect status 401
```

### Cloud Security Example

```cyberguard
target cloud "aws"

check "Storage Security":
    inspect storage
    expect public_access false
    expect encryption enabled

check "IAM Policies":
    inspect iam
    expect root_access_disabled true
    expect mfa_enabled true
```

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Code Style

- Python 3.11+
- Follow PEP 8
- Use type hints
- Write docstrings
- 100 character line length

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

CyberGuard Contributors

## 🙏 Acknowledgments

- Inspired by declarative security testing frameworks
- Built with [Typer](https://typer.tiangolo.com/) for CLI

## 📞 Contact

For questions and feedback:
- GitHub Issues: https://github.com/karthiga117/PSE-CyberGuard/issues
- GitHub Discussions: https://github.com/karthiga117/PSE-CyberGuard/discussions

---

**Note:** CyberGuard is in early development (Phase 1). Core functionality for language parsing and security testing will be implemented in subsequent phases.
