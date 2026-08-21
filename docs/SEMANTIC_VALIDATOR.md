# Semantic Validation

CyberGuard keeps a strict validation pipeline:

source
  ↓
Lexer
  ↓
Parser
  ↓
AST
  ↓
SemanticValidator
  ↓
Execution

The lexer checks lexical validity, the parser checks syntactic validity, and the semantic validator checks whether the resulting AST makes sense according to CyberGuard security rules.

## What the SemanticValidator checks

The semantic validator inspects the AST rather than re-reading source text. It enforces CyberGuard v0.1 constraints such as:

- valid web target URLs and supported cloud providers
- request path and HTTP method validation
- exactly one request per test and request ordering
- supported authentication, injection, and detection values
- valid assertion values and cloud property names
- duplicate and empty test/check names
- duplicate cloud resources and inspection ordering

## API

```python
from cyberguard.semantic import SemanticValidator

validator = SemanticValidator()
validator.validate(program_ast)
```

A semantic validation failure raises `SemanticError` with the rule ID, source line, column, and an optional suggestion.
