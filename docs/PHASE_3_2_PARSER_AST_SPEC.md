# Phase 3.2 — Parser & AST Language Specification

## 1. Purpose

This document defines the syntax-only Phase 3.2 parser and AST specification for the frozen CyberGuard DSL v0.1.

It is intentionally limited to:

- grammar
- statement containment
- AST data shape
- parser error rules
- source location metadata

This specification does not implement a parser, does not define execution behavior, and does not add new language features.

The Parser is responsible only for:

- consuming the frozen Lexer token stream
- validating syntax and block structure
- constructing an AST that reflects source structure
- preserving source locations
- failing fast on invalid syntax

The Parser is not responsible for:

- semantic validation
- HTTP or cloud operations
- scanning, detection, or reporting logic
- runtime evaluation

## 2. Scope and non-goals

### In scope

- the frozen token contract
- the exact grammar accepted by Phase 3.2
- indentation-driven block structure
- AST node shapes for all supported syntax
- parser error categories
- valid and invalid examples

### Out of scope

- parser implementation
- AST class implementation
- lexer changes
- new tokens
- new keywords
- new operators
- execution logic
- semantic validation

## 3. Frozen Lexer contract

The Phase 3.1 Lexer is complete and frozen. Phase 3.2 must consume its token stream as-is.

The Parser must not:

- add token types
- remove token types
- change token meanings
- change keyword meanings
- change operators
- change indentation rules
- change string rules
- change comment rules

The Parser relies on these token categories:

| Token | Purpose |
| --- | --- |
| KEYWORD | Reserved DSL words and frozen value keywords |
| IDENTIFIER | Unreserved names such as `username` |
| INTEGER | Numeric literal |
| STRING | Quoted literal |
| OPERATOR | `:` `==` `!=` |
| NEWLINE | End of line |
| INDENT | Block open |
| DEDENT | Block close |
| EOF | End of file |

If a grammar rule appears to require a lexer change, document it as an incompatibility rather than changing the lexer.

### Frozen keyword vocabulary

The parser may use only these frozen keyword spellings:

- target
- web
- cloud
- test
- request
- authenticate
- with
- inject
- detect
- expect
- resource
- inspect
- sql
- sql-error
- basic
- bearer
- api-key
- cookie
- storage
- iam
- header
- body
- status
- true
- false
- enabled
- disabled
- GET
- POST
- PUT
- DELETE
- PATCH
- HEAD
- OPTIONS
- contains
- not-contains
- missing
- exists
- not-exists

### Frozen operators

Only these operators are part of the frozen v0.1 grammar:

- `:`
- `==`
- `!=`

Standalone `=` is invalid. Arithmetic and ordering operators are not part of the grammar.

## 4. Parser model

The recommended architecture is a recursive-descent parser.

Conceptually, it maintains:

- a token stream
- a current token
- limited lookahead
- `consume`
- `expect`
- EOF handling
- fail-fast error reporting

The parser should not infer syntax from raw spaces. INDENT and DEDENT are already normalized by the lexer.

## 5. Authoritative EBNF

This is the single authoritative grammar for Phase 3.2.

`BlankLine` is a syntax-only helper rule. It does not produce AST nodes and it does not change block structure.

### 5.1 Top-level structure

```ebnf
Program
    ::= BlankLine* TargetBlock (BlankLine* TargetBlock)* BlankLine* EOF

BlankLine
    ::= NEWLINE

TargetBlock
    ::= "target" ":" TargetKind NEWLINE INDENT TargetBody DEDENT

TargetKind
    ::= "web" | "cloud"

TargetBody
    ::= WebTargetBody
    |   CloudTargetBody
```

### 5.2 Web target body

```ebnf
WebTargetBody
    ::= TestBlock+

TestBlock
    ::= "test" ":" TestKind NEWLINE INDENT TestBody DEDENT

TestKind
    ::= "request"
```

### 5.3 Request test body

```ebnf
TestBody
    ::= RequestStatement NEWLINE
        [ AuthenticationStatement NEWLINE ]
        [ WithStatement NEWLINE ]
        [ InjectionStatement NEWLINE ]
        [ DetectionStatement NEWLINE ]
        [ ExpectationStatement NEWLINE ]
```

Cardinality implied by the grammar:

- `RequestStatement` exactly 1
- `AuthenticationStatement` 0..1
- `WithStatement` 0..1
- `InjectionStatement` 0..1
- `DetectionStatement` 0..1
- `ExpectationStatement` 0..1

The order is fixed. Duplicate singleton statements are syntax errors.

The keyword `request` is context-sensitive:

- after `test:` it is a `TestKind`
- inside a request test body it is a `RequestStatement`

### 5.4 Cloud target body

```ebnf
CloudTargetBody
    ::= ResourceStatement NEWLINE
        [ InspectionStatement NEWLINE ]
```

Cardinality implied by the grammar:

- `ResourceStatement` exactly 1
- `InspectionStatement` 0..1

Cloud statements are valid only under `target: cloud`.

### 5.5 Statements

```ebnf
RequestStatement
    ::= "request" ":" HttpMethod

HttpMethod
    ::= "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS"

AuthenticationStatement
    ::= "authenticate" ":" AuthenticationMethod

AuthenticationMethod
    ::= "basic" | "bearer" | "api-key" | "cookie"

InjectionStatement
    ::= "inject" ":" "sql"

DetectionStatement
    ::= "detect" ":" "sql-error"

ExpectationStatement
    ::= "expect" ":" ExpectationKind

ExpectationKind
    ::= "missing" | "exists" | "contains" | "not-contains" | "not-exists" | "enabled" | "disabled"

ResourceStatement
    ::= "resource" ":" ResourceKind

ResourceKind
    ::= "storage" | "iam"

InspectionStatement
    ::= "inspect" ":" InspectionTarget

InspectionTarget
    ::= "storage" | "iam" | "header" | "body" | "status"
```

### 5.6 Expression grammar

```ebnf
WithStatement
    ::= "with" ":" ComparisonExpression

ComparisonExpression
    ::= IdentifierValue Comparator Value

Comparator
    ::= "==" | "!="

Value
    ::= StringLiteral
    |   IntegerLiteral
    |   IdentifierValue
    |   BooleanLiteral

BooleanLiteral
    ::= "true" | "false"

IdentifierValue
    ::= IDENTIFIER

StringLiteral
    ::= STRING

IntegerLiteral
    ::= INTEGER
```

Only the comparison form above is supported. There is no general expression language.

## 6. Statement containment matrix

This matrix is authoritative. Any parent/child combination not listed here is invalid.

| Parent | Allowed child | Cardinality |
| --- | --- | --- |
| Program | TargetBlock | 1..N |
| TargetBlock(web) | TestBlock | 1..N |
| TargetBlock(cloud) | ResourceStatement | exactly 1 |
| TargetBlock(cloud) | InspectionStatement | 0..1 |
| TestBlock(request) | RequestStatement | exactly 1 |
| TestBlock(request) | AuthenticationStatement | 0..1 |
| TestBlock(request) | WithStatement | 0..1 |
| TestBlock(request) | InjectionStatement | 0..1 |
| TestBlock(request) | DetectionStatement | 0..1 |
| TestBlock(request) | ExpectationStatement | 0..1 |

Not allowed:

- `ResourceStatement` under `TestBlock`
- `InspectionStatement` under `TestBlock`
- `TestBlock` under `TargetBlock(cloud)`
- any unsupported `TestKind` other than `request`

## 7. AST model

The AST is a syntax tree only. It stores structure and values, not behavior.

### 7.1 SourceLocation

All AST nodes that carry source information reference:

```text
SourceLocation
  line: int
  column: int
```

The location is the starting position of the node in source text.

### 7.2 Enumerations

These are not AST nodes; they are constrained field values:

- `TargetKind = web | cloud`
- `TestKind = request`
- `HttpMethod = GET | POST | PUT | DELETE | PATCH | HEAD | OPTIONS`
- `AuthenticationMethod = basic | bearer | api-key | cookie`
- `ResourceKind = storage | iam`
- `InspectionTarget = storage | iam | header | body | status`
- `ExpectationKind = missing | exists | contains | not-contains | not-exists | enabled | disabled`
- `Comparator = == | !=`

### 7.3 AST node definitions

| Node | Purpose | Fields | Required / optional | Child nodes | Cardinality | Parent context | Source location |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Program | Root file node | `targets: list[TargetBlock]` | required | `TargetBlock+` | exactly 1 per file | none | required |
| TargetBlock | Domain block | `kind: TargetKind`, `body: list[TargetChild]` | both required | web: `TestBlock+`; cloud: `ResourceStatement` and optional `InspectionStatement` | 1..N per file | Program | required |
| TestBlock | Web test block | `kind: TestKind`, `body: list[TestChild]` | both required | `RequestStatement`, optional singleton statements in fixed order | 1..N under web target | `TargetBlock(web)` | required |
| RequestStatement | HTTP method selector | `method: HttpMethod` | required | none | exactly 1 per request test | `TestBlock(request)` | required |
| AuthenticationStatement | Authentication selector | `method: AuthenticationMethod` | required | none | 0..1 per request test | `TestBlock(request)` | required |
| WithStatement | Comparison filter | `expression: ComparisonExpression` | required | `ComparisonExpression` | 0..1 per request test | `TestBlock(request)` | required |
| InjectionStatement | Injection intent | `kind: "sql"` | required | none | 0..1 per request test | `TestBlock(request)` | required |
| DetectionStatement | Detection intent | `kind: "sql-error"` | required | none | 0..1 per request test | `TestBlock(request)` | required |
| ExpectationStatement | Expected outcome | `kind: ExpectationKind` | required | none | 0..1 per request test | `TestBlock(request)` | required |
| ResourceStatement | Cloud resource declaration | `kind: ResourceKind` | required | none | exactly 1 per cloud target | `TargetBlock(cloud)` | required |
| InspectionStatement | Cloud inspection selector | `kind: InspectionTarget` | required | none | 0..1 per cloud target | `TargetBlock(cloud)` | required |
| ComparisonExpression | Binary comparison | `left: IdentifierValue`, `operator: Comparator`, `right: ValueNode` | all required | `IdentifierValue`, `ValueNode` | exactly 1 per WithStatement | `WithStatement` | required |
| StringLiteral | String value node | `value: str` | required | none | as needed in `Value` | `ComparisonExpression` | required |
| IntegerLiteral | Integer value node | `value: int` | required | none | as needed in `Value` | `ComparisonExpression` | required |
| BooleanLiteral | Boolean-like value node | `value: bool` | required | none | as needed in `Value` | `ComparisonExpression` | required |
| IdentifierValue | Identifier value node | `name: str` | required | none | as needed in `Value` | `ComparisonExpression` | required |

`TargetChild` is the union of `TestBlock`, `ResourceStatement`, and `InspectionStatement`.

`TestChild` is the ordered union of `RequestStatement`, `AuthenticationStatement`, `WithStatement`, `InjectionStatement`, `DetectionStatement`, and `ExpectationStatement`.

`ValueNode` is the union of `StringLiteral`, `IntegerLiteral`, `BooleanLiteral`, and `IdentifierValue`.

## 8. Grammar to AST traceability

Every grammar rule maps to an AST node or to a constrained field value.

| Grammar rule | AST node or field | Valid example |
| --- | --- | --- |
| Program | Program | `target: web` ... `target: cloud` ... |
| TargetBlock | TargetBlock | `target: web` |
| TargetKind | `TargetBlock.kind` | `web` |
| WebTargetBody | `TargetBlock.body` | `test: request` ... |
| CloudTargetBody | `TargetBlock.body` | `resource: storage` |
| TestBlock | TestBlock | `test: request` |
| TestKind | `TestBlock.kind` | `request` |
| RequestStatement | RequestStatement | `request: GET` |
| AuthenticationStatement | AuthenticationStatement | `authenticate: basic` |
| WithStatement | WithStatement | `with: username == "admin"` |
| ComparisonExpression | ComparisonExpression | `username == "admin"` |
| InjectionStatement | InjectionStatement | `inject: sql` |
| DetectionStatement | DetectionStatement | `detect: sql-error` |
| ExpectationStatement | ExpectationStatement | `expect: exists` |
| ResourceStatement | ResourceStatement | `resource: storage` |
| InspectionStatement | InspectionStatement | `inspect: iam` |
| HttpMethod | `RequestStatement.method` | `GET` |
| AuthenticationMethod | `AuthenticationStatement.method` | `bearer` |
| ResourceKind | `ResourceStatement.kind` | `storage` |
| InspectionTarget | `InspectionStatement.kind` | `iam` |
| ExpectationKind | `ExpectationStatement.kind` | `missing` |
| Comparator | `ComparisonExpression.operator` | `==` |
| Value | `ValueNode` | `"admin"`, `42`, `username`, `true` |

Reverse mapping is complete as well:

- every AST node above has exactly one grammar source
- every grammar rule above has exactly one AST representation or constrained field value
- every valid example below maps to a grammar rule and an AST shape

## 9. Parser / semantic / execution boundaries

### Parser

The Parser handles:

- syntax
- grammar
- token ordering
- block structure
- indentation tokens
- required and optional statements
- syntax errors

### Semantic validator

The semantic validator handles:

- meaning
- cross-reference validation
- configuration rules
- security-specific consistency

### Execution engine

The execution engine handles:

- HTTP calls
- cloud operations
- security checks
- scanning
- detection
- reporting

The Parser and AST must not contain semantic validation or execution logic.

## 10. Valid examples

### 10.1 Minimal valid program

```text
target: web
    test: request
        request: GET
```

### 10.2 Web request with authentication

```text
target: web
    test: request
        request: GET
        authenticate: basic
```

### 10.3 Web request with comparison

```text
target: web
    test: request
        request: GET
        with: username == "admin"
```

### 10.4 Web request with injection, detection, and expectation

```text
target: web
    test: request
        request: POST
        inject: sql
        detect: sql-error
        expect: exists
```

### 10.5 Cloud target

```text
target: cloud
    resource: storage
    inspect: iam
```

### 10.6 Program with two targets

```text
target: web
    test: request
        request: GET
target: cloud
    resource: storage
```

## 11. Invalid syntax examples

Each invalid example states the input, the expected form, the actual form, and the parser error category.

### 11.1 Missing colon

| Item | Value |
| --- | --- |
| Input | `target web` |
| Expected | `target: web` |
| Actual | KEYWORD followed by KEYWORD without `:` |
| Parser error category | Missing colon |

### 11.2 Missing value

| Item | Value |
| --- | --- |
| Input | `request:` |
| Expected | `request: GET` and a valid HTTP method |
| Actual | End of line after `:` |
| Parser error category | Missing value |

### 11.3 Unsupported keyword

| Item | Value |
| --- | --- |
| Input | `target: api` |
| Expected | `target: web` or `target: cloud` |
| Actual | Unsupported target keyword |
| Parser error category | Unsupported keyword |

### 11.4 Invalid TestKind

| Item | Value |
| --- | --- |
| Input | `test: detect` |
| Expected | `test: request` |
| Actual | Unsupported test kind |
| Parser error category | Invalid TestKind |

### 11.5 Invalid statement parent

| Item | Value |
| --- | --- |
| Input | `target: web` then `resource: storage` |
| Expected | `resource` only under `target: cloud` |
| Actual | Cloud statement inside a web target |
| Parser error category | Invalid parent context |

### 11.6 Duplicate singleton statement

| Item | Value |
| --- | --- |
| Input | `request: GET` then `request: POST` inside the same request test block |
| Expected | Exactly one request statement |
| Actual | Duplicate `request` statement |
| Parser error category | Duplicate singleton statement |

### 11.7 Invalid indentation

| Item | Value |
| --- | --- |
| Input | `target: web` then a line indented by an unexpected amount |
| Expected | INDENT and DEDENT emitted only for valid nested blocks |
| Actual | Inconsistent indentation level |
| Error ownership | LexerError |

### 11.8 Unexpected INDENT

| Item | Value |
| --- | --- |
| Input | `    target: web` |
| Expected | Top-level target block at column 1 |
| Actual | INDENT before any block opener |
| Parser error category | Unexpected INDENT |

### 11.9 Unexpected DEDENT

| Item | Value |
| --- | --- |
| Input | `target: web` then an immediate dedent with no open nested block |
| Expected | DEDENT only when closing an open block |
| Actual | Extra DEDENT token |
| Parser error category | Unexpected DEDENT |

### 11.10 Malformed expression

| Item | Value |
| --- | --- |
| Input | `with: username ==` |
| Expected | `with: username == "admin"` or another supported value |
| Actual | Missing right operand |
| Parser error category | Malformed expression |

### 11.11 Unsupported operator

| Item | Value |
| --- | --- |
| Input | `with: username >= "admin"` |
| Expected | `==` or `!=` |
| Actual | `>=` |
| Parser error category | Unsupported operator |

### 11.12 Unexpected EOF

| Item | Value |
| --- | --- |
| Input | `target: web` |
| Expected | A web target body containing at least one test block |
| Actual | End of file before the required body appeared |
| Parser error category | Unexpected EOF |

## 12. Validity rules and cardinality summary

### TestKind

Only one `TestKind` is supported in v0.1:

- `request`

### Web target structure

- `target: web` must contain one or more `test: request` blocks
- each request test block must contain exactly one `request: METHOD`
- each of `authenticate`, `with`, `inject`, `detect`, and `expect` may appear at most once
- the statement order is fixed by the grammar
- `resource` and `inspect` are not valid inside web test blocks

### Cloud target structure

- `target: cloud` must contain exactly one `resource: ...`
- `inspect: ...` is optional and may appear at most once
- `resource` must come before `inspect`
- `test` blocks are not valid inside cloud targets

### Values

Only these value forms are accepted in `with` expressions:

- STRING
- INTEGER
- IDENTIFIER
- BOOLEAN literal values: `true`, `false`

No additional value types are defined.

## 13. Open questions / ambiguities

No unresolved grammar ambiguities remain.

Any syntax not listed in this document is invalid.

## 14. Acceptance criteria

This specification is complete only if all of the following are true:

- the grammar is complete
- the grammar is unambiguous
- the AST matches the grammar
- the examples match the grammar
- the containment matrix matches the grammar
- cardinality is explicit
- `TestKind` is unambiguous
- cloud structure is explicit
- expression grammar is explicit
- `SourceLocation` is defined
- invalid syntax examples exist
- parser / semantic / execution boundaries are clear
- no lexer changes are required
- no implementation is described or added

## 15. Final note

This document is the authoritative Phase 3.2 design boundary. It is intended to be directly implementable later by a recursive-descent parser without additional assumptions.
