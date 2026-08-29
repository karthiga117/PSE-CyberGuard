# CyberGuard Security Capabilities Design

## 1. Executive Summary

CyberGuard's current implementation is a layered system with a stable core:

- Lexer
- Parser
- AST
- Semantic Validation
- Web Execution Engine v0.1

The project currently contains a small but real set of security-oriented constructs, but it does not yet define a complete security runtime. The present state is best described as:

- some security semantics are expressed in the DSL and AST,
- semantic validation enforces a subset of them,
- the Web Execution Engine executes HTTP requests and status assertions,
- authentication, injection, detection, expectation, and cloud-security runtime behavior remain partial or undefined.

The most important architectural fact is that the project already distinguishes between:

- ExecutionResult: execution- and transport-oriented outcomes
- security intent: capability-specific behavior that is not yet modeled as a complete first-class runtime layer

The correct Security Capabilities design is therefore a thin layer around the validated AST and the existing Web Execution Engine, not a redesign of the stable core. It must reuse established project semantics and avoid inventing unsupported DSL syntax, AST nodes, or runtime behaviors.

### Important project realities

- The DSL does not currently define target URL syntax; the runtime target URL is supplied externally in tests.
- The parser and AST include `RequestStatement.path`, but current runtime path handling is limited to URL construction/concatenation.
- Authentication, injection, detection, expectation, and cloud-property constructs exist as syntax/validation constructs, but their runtime behavior is not implemented.
- Security findings and security result objects are not currently defined in the existing runtime.
- The current AST enforces one `RequestStatement` per `TestBlock`, so multi-request and multi-payload execution are not currently supported.

The design therefore centers on:

- validated AST
- Web Execution Engine
- `SecurityCapability
- `SecurityContext
- `SecurityFinding
- `SecurityResult

No generic security framework should be assumed.

---

## 2. Current Security Capabilities

| Capability | DSL Representation | AST Representation | Semantic Validation | Runtime Requirement | Current Status |
| --- | --- | --- | --- | --- | --- |
| HTTP request execution | `request: GET / POST / PUT / DELETE / PATCH / HEAD / OPTIONS` | `RequestStatement(method, path?)` | Validates method and optional path format | Execute HTTP request via Web Execution Engine | **CURRENTLY DEFINED** |
| Status assertion | `with: status == 200` / `with: status != 500` | `ComparisonExpression(left=status, operator, right=IntegerLiteral)` | Validates status is integer and valid HTTP code | Compare response status against expected value | **CURRENTLY DEFINED** |
| Authentication selector | `authenticate: basic / bearer / api-key / cookie` | `AuthenticationStatement(method)` | Validates supported methods | Apply authentication metadata to a request | **PARTIALLY DEFINED** |
| Injection intent | `inject: sql` | `InjectionStatement(kind="sql")` | Validates supported kind | Mutate request and analyze response | **PARTIALLY DEFINED** |
| Detection intent | `detect: sql-error` | `DetectionStatement(kind="sql-error")` | Validates supported kind | Inspect response for detection evidence | **PARTIALLY DEFINED** |
| Expectation semantics | `expect: exists / missing / contains / not-contains / not-exists / enabled / disabled` | `ExpectationStatement(kind)` | Validates supported kinds | Evaluate the requested expectation | **PARTIALLY DEFINED** |
| Cloud property checks | `with: public_access == false` | `ComparisonExpression` on cloud property names | Validates supported cloud properties and scalar rules | Evaluate cloud property checks | **PARTIALLY DEFINED** |
| Target URL handling | Not parsed by DSL today | `TargetBlock.url` | URL validity check where applicable | Supply/build final request URL | **PARTIALLY DEFINED** |
| Request path handling | Request path is optional | `RequestStatement.path` | Path must begin with `/` if present | Combine base target URL with request path | **PARTIALLY DEFINED** |
| Security finding model | Not defined in DSL | Not defined in existing AST/runtime | No existing semantic rule | Represent security-relevant evidence | **NOT CURRENTLY DEFINED** |
| Security result model | Not defined in DSL | Not defined in existing AST/runtime | No existing semantic rule | Aggregate capability outcomes | **NOT CURRENTLY DEFINED** |

### Capability-by-capability meaning

#### 1. HTTP Request Execution

- The web target is request-driven.
- A request test is built around a `RequestStatement` plus optional evaluation.
- The current runtime sends an HTTP request to a supplied target URL and captures the response.

#### 2. Status Assertion

- This is the proven, implemented assertion.
- It uses a `ComparisonExpression` against response status.
- This is the only fully realized runtime assertion described by the current project state.

#### 3. Authentication Selection

The DSL supports:

- `basic`
- `bearer`
- `api-key`
- `cookie`

The AST stores the method string.

No runtime behavior currently converts the selector into headers, cookies, or token handling.

#### 4. Injection Intent

- The DSL contains `inject: sql`.
- Semantic validation recognizes `sql`.
- No payload model or request mutation flow currently exists.

#### 5. Detection Intent

- The DSL contains `detect: sql-error`.
- Semantic validation recognizes `sql-error`.
- No response analysis engine currently exists.

#### 6. Expectation Statements

- The AST includes `ExpectationStatement(kind)`.
- Validation recognizes the supported expectation kinds.
- Runtime semantics are not implemented.

#### 7. Cloud Property Checks

- Cloud targets and property comparisons are semantically defined.
- The current project does not implement a cloud runtime.

#### 8. Target URL Handling

- Current tests supply or override `TargetBlock.url` after parsing.
- This indicates that URL syntax is not currently parsed by the DSL.
- The runtime consumes the target URL when supplied.

#### 9. Request Path Handling

- `RequestStatement.path` exists and is semantically validated.
- When present, the engine combines the base target URL and path to construct the final request URL.

#### 10. Security Finding Model

- A security finding model is not currently defined in the existing codebase.
- It is a proposed runtime model for the Security Capabilities phase and must not be represented as an already-implemented feature.

---

## 3. DSL → AST → Semantic → Runtime Mapping

### Core mapping

```text
DSL
  ↓
AST
  ↓
Semantic Validation
  ↓
Validated AST
  ↓
Security Capability / Execution Coordination
  ↓
Web Execution Engine
  ↓
Security Analysis
  ↓
Security Result / Finding
```

The security capability layer consumes validated constructs. It must not bypass semantic validation.

### Mapping examples

#### A. Request + status check

DSL:

```text
target: web
test: request
request: GET
with: status == 200
```

AST:

- `TargetBlock`
- `TestBlock`
- `RequestStatement(method="GET", path?)`
- `WithStatement(expression=ComparisonExpression(...status...))`

Semantic validation:

- HTTP method is allowed.
- Status comparison is valid.
- Integer uses a valid HTTP status range.
- Request path is valid if present.

Runtime behavior:

1. Obtain the target URL.
2. Build the final request URL.
3. Send the HTTP request.
4. Receive the response.
5. Evaluate the status assertion.

Result:

- `ExecutionResult.SUCCESS` when the request succeeds and the assertion passes.
- `ExecutionStatus.ASSERTION_FAILURE` when the response is received but the assertion fails.
- `ExecutionStatus.EXECUTION_ERROR` when request execution fails.

#### B. Authentication

DSL:

```text
authenticate: bearer
```

AST:

```text
AuthenticationStatement(method="bearer")
```

Semantic validation:

- Method is supported.

Runtime behavior:

- Not currently defined.
- A future capability may use this statement to modify an executable request once credential-source and secret-handling semantics are specified.

Result:

- No current security result is produced.

#### C. Injection

DSL:

```text
inject: sql
```

AST:

```text
InjectionStatement(kind="sql")
```

Semantic validation:

- Kind is supported.

Runtime behavior:

- Not implemented.
- Payload, mutation position, mutation rules, and analysis semantics are unspecified.

Result:

- No current security result is produced.

#### D. Detection

DSL:

```text
detect: sql-error
```

AST:

```text
DetectionStatement(kind="sql-error")
```

Semantic validation:

- Kind is supported.

Runtime behavior:

- Not implemented.
- Detection criteria and response-analysis semantics are unspecified.

Result:

- No current security result is produced.

#### E. Cloud property check

DSL:

```text
with: public_access == false
```

AST:

```text
ComparisonExpression(
    left=IdentifierValue("public_access"),
    ...
)
```

Semantic validation:

- Property is a known cloud property.
- Scalar type is valid.

Runtime behavior:

- Not implemented because cloud inspection/runtime integration is not currently defined.

Result:

- No current security result is produced.

---

## 4. Security Runtime Architecture

The architecture should remain thin and grounded in the actual project:

```text
Validated AST
     ↓
Execution / Security Coordination
     ↓
┌──────────────────────────────────────┐
│ Security Capability                  │
│                                      │
│ - authentication preparation         │
│ - request mutation                   │
│ - assertion evaluation               │
│ - response detection                 │
│ - cloud property evaluation          │
└──────────────────┬───────────────────┘
                   ↓
          Web Execution Engine
                   ↓
             ExecutionResult
                   ↓
          Security Analysis
                   ↓
         SecurityResult / Finding
```

The key correction is that capabilities that need to modify a request must participate **before** HTTP execution, while response-based capabilities operate **after** execution. The Web Execution Engine remains responsible for transport.

### Runtime stages

1. **Validated AST**
   - Input to runtime.
   - No parsing or semantic validation is repeated here.

2. **Capability preparation/evaluation**
   - Determine which validated security statements apply.
   - Prepare authentication or request mutations when those capabilities are implemented.
   - Evaluate checks that do not require HTTP transport.

3. **Web Execution Engine**
   - Build the final URL.
   - Execute the HTTP request.
   - Return the existing `ExecutionResult`/response information.

4. **Security Analysis**
   - Interpret execution and response data in security terms.
   - Produce security findings or a security check outcome.

5. **Security Result**
   - Aggregate findings and overall security evaluation without changing the meaning of `ExecutionResult`.

### Boundaries

#### 1. Validated AST

Semantic validation guarantees that structural and semantic rules have already passed.

The runtime can therefore rely on validated constructs such as:

- supported methods
- valid request paths
- valid comparison shapes
- valid injection/detection kinds
- valid cloud properties
- valid target information where applicable

#### 2. Web Execution Engine

- Remains HTTP transport-oriented.
- Builds URLs, executes requests, and returns execution information.
- Must not become the security-analysis engine.
- Should not own injection, detection, authentication policy, or security finding aggregation.

#### 3. Security Capability

A capability handles one validated security concern.

Depending on its type, it may:

- evaluate a status assertion,
- prepare authentication,
- create a modified request,
- inspect a response,
- evaluate a cloud property,
- produce a security finding.

A capability must not own parsing, semantic validation, or the underlying HTTP transport.

#### 4. Security Analysis

- Converts execution data into security meaning.
- Evaluates evidence produced by a capability.
- Distinguishes a transport failure from a security finding.

Example:

```text
HTTP request executed
        ↓
Response received
        ↓
Detection capability inspects response
        ↓
Evidence found / not found
        ↓
Security outcome
```

#### 5. Security Result / Finding

- `SecurityFinding` represents a specific security-relevant observation.
- `SecurityResult` represents the overall security evaluation and may contain zero or more findings.
- Neither replaces or changes `ExecutionResult`.

---

## 5. Minimum Justified Abstractions

### `SecurityCapability`

**Responsibility**

Execute or evaluate one validated security concern over runtime context.

**Inputs**

- validated AST item
- `SecurityContext`

**Outputs**

- capability outcome
- zero or more `SecurityFinding` objects

**Dependencies**

- `SecurityContext`
- execution services where required

**Why required**

The current project contains multiple security concerns in the AST and semantic layer, while the execution layer is not structured to implement them directly.

**Why not combine with the execution engine**

The execution engine must remain transport-focused.

### `SecurityContext`

**Responsibility**

Carry the minimal runtime data required by a security capability.

**Inputs**

- target
- test
- original request
- executable request when applicable
- response when available
- capability
- findings accumulated so far

**Optional state**

- modified request
- payload
- authentication state
- previous results
- variables

**Why required**

Security logic may need data beyond the raw execution result.

**Why not make it a generic runtime container**

The project does not provide evidence that a large, generic context object is required.

### `SecurityFinding`

**Responsibility**

Represent a specific security-relevant observation produced by a capability.

**Inputs**

- capability
- evidence
- target/test metadata
- request/response evidence
- outcome

**Output**

- structured finding object

**Why required**

A security observation is not equivalent to transport failure or an ordinary assertion failure.

### `SecurityResult`

**Responsibility**

Represent the overall security evaluation for a test or capability execution.

**Inputs**

- zero or more findings
- overall security outcome

**Outputs**

- overall status
- findings

**Why required**

A security capability may produce zero, one, or multiple findings, while the caller still needs a single security-level outcome.

### Abstractions not currently justified

Do not introduce these without explicit requirements:

- generic `DetectionEngine`
- generic `InjectionExecutor`
- broad `AuthenticationStrategy`
- broad plugin architecture
- large reporting framework
- persistence layer

Concrete capability implementations can be added later without committing the project to these broader abstractions.

---

## 6. Security Capability Interface

The recommended contract is intentionally narrow:

```text
evaluate(validated_ast_node, context) -> capability outcome
```

A capability outcome may contain:

```text
- security status
- zero or more SecurityFinding objects
- optional execution/mutation information
```

A capability may internally use helper functions such as:

```text
create_finding(...) -> SecurityFinding
```

The interface should not force every capability to perform the same kind of work. Authentication and injection may prepare a request before execution, while detection and some assertions evaluate data after execution.

### Capability categories

1. **HTTP assertion capability**
   - Already present in project semantics.
   - Evaluates status comparison.

2. **Injection capability**
   - Future capability.
   - Works from `InjectionStatement`.

3. **Detection capability**
   - Future capability.
   - Works from `DetectionStatement`.

4. **Authentication capability**
   - Future capability.
   - Works from `AuthenticationStatement`.

5. **Expectation capability**
   - Future capability.
   - Works from `ExpectationStatement`.

6. **Cloud security capability**
   - Future capability.
   - Works from cloud target properties and inspection semantics.

### Design rule

Each capability should be scoped to one security intent and should not manage:

- parsing
- semantic validation
- low-level HTTP transport
- persistence
- broad reporting

---

## 7. Security Context

The current project does not define a giant runtime object. A minimal context is sufficient.

### Recommended `SecurityContext` fields

**Required when applicable:**

- `target`
- `test`
- `original_request`
- `capability`

**Available after HTTP execution:**

- `response`
- `execution_result`

**Optional:**

- `modified_request`
- `payload`
- `auth_state`
- `findings`
- `previous_results`
- `variables`

The response should not be required for capabilities that operate before HTTP execution.

### Why this is sufficient

The current runtime is fundamentally request/response-driven. The security layer needs:

- the target being tested
- the test that produced the operation
- the original request
- the executable/modified request when applicable
- the response when available
- execution information
- optional mutation details

There is no evidence in the project that a large generic context object is required.

---

## 8. Security Result and Finding Model

This is a critical design boundary.

### `ExecutionResult`

Current meaning:

- runtime request succeeded or failed
- assertion passed or failed
- execution error occurred

Examples:

- HTTP timeout → `EXECUTION_ERROR`
- connection failure → `EXECUTION_ERROR`
- status mismatch → `ASSERTION_FAILURE`
- status match → `SUCCESS`

`ExecutionResult` describes execution behavior. It does not by itself establish a vulnerability.

### `SecurityFinding`

A security finding represents a specific security-relevant observation or issue produced by a security capability.

Examples:

- a response contains evidence matching a future SQL-error detection rule,
- a candidate injection operation produces evidence indicating a possible weakness,
- a cloud property violates a configured security condition.

The statement that an authentication selector exists without a credential source should be treated as a **configuration/specification gap**, not automatically as a vulnerability finding.

### `SecurityResult`

`SecurityResult` represents the security-level outcome of evaluating a capability or test.

Recommended conceptual structure:

```text
SecurityResult
├── outcome
└── findings[]
```

Possible outcome values should be finalized when the security result contract is implemented. Do not introduce exact enum names until they are specified.

### Recommended relationship

```text
ExecutionResult
    └── transport/execution outcome

SecurityFinding
    └── one security-relevant observation

SecurityResult
    ├── overall security outcome
    └── zero or more SecurityFinding objects
```

### Recommended `SecurityFinding` fields

**Required for the initial model:**

- `capability`
- `target`
- `test`
- `evidence`
- `outcome`

**Request/response evidence, when applicable:**

- request metadata
- response metadata
- relevant response evidence

**Optional:**

- `rule`
- `severity`
- `title`
- `description`
- `expected`
- `actual`
- `remediation`

**Future:**

- `cwe`
- `confidence`
- `compliance_tag`
- report metadata

### Why these fields are required

- `capability`: identifies what evaluated the issue.
- `target`: identifies what was assessed.
- `test`: identifies which test produced the observation.
- `evidence`: explains what supports the outcome.
- `outcome`: records whether the security check passed, failed, or was inconclusive.

Request and response data should be included only when relevant and should be sanitized.

### Decision

`SecurityFinding` should be a separate result object, not embedded inside `ExecutionResult`.

A `SecurityResult` wrapper can aggregate one or more findings and an overall security outcome.

---

## 9. Injection Design

### Current status

Injection is **PARTIALLY DEFINED**.

The project currently defines:

- `InjectionStatement(kind="sql")`
- semantic validation supports `sql`
- no runtime injection behavior

Therefore:

> Injection is not currently implemented as a real runtime capability.

### Current intended mapping

```text
Original Request
      ↓
Injection Operation
      ↓
Modified Request
      ↓
Web Execution Engine
      ↓
Response
      ↓
Detection / Analysis
      ↓
Security Finding
```

This is a **future execution flow**, not current runtime behavior.

### Actual missing requirements

The project does not define:

- payload source
- payload representation
- injection position
- request mutation rules
- multi-payload behavior
- detection criteria for SQL-error responses
- aggregation semantics across payload attempts

These are **SPECIFICATION GAPS**.

### Design recommendation

Until these are specified, injection should remain a future capability that builds on:

- validated `InjectionStatement`
- request mutation semantics
- `SecurityContext`
- `SecurityFinding`
- `SecurityResult`

No payloads or additional DSL syntax should be invented based on assumptions.

---

## 10. Detection Design

### Current status

Detection is **PARTIALLY DEFINED**.

Current AST:

```text
DetectionStatement(kind="sql-error")
```

Semantic validation:

- accepts `sql-error`

Current runtime:

- none

### Minimal future runtime flow

```text
Response
   ↓
Detection Capability
   ↓
Detection Outcome
   ↓
Security Finding
```

### Missing requirements

The project does not define:

- which response fields are inspected
- exact detection logic
- pass/fail semantics
- result model for detection
- relationship between detection evidence and vulnerability findings

This is a **SPECIFICATION GAP**.

### Recommendation

Detection should be implemented as a future capability once response-analysis rules are specified. It should reuse the same `SecurityContext`, `SecurityFinding`, and `SecurityResult` model.

---

## 11. Authentication Design

### Current status

Authentication is **PARTIALLY DEFINED**.

Supported methods:

- `basic`
- `bearer`
- `api-key`
- `cookie`

AST:

```text
AuthenticationStatement(method)
```

Validation:

- method must be recognized

Runtime behavior:

- none

### Missing requirements

The project does not define:

- credential source
- token or cookie creation
- header construction
- request mutation behavior
- state across tests
- secret storage/retrieval mechanism

### Conclusion

Authentication is partially defined, but runtime behavior is **NOT CURRENTLY DEFINED**.

It should be implemented as a future capability that prepares an executable request. It should not be integrated as security-analysis logic inside the Web Execution Engine.

### Recommended placement

Authentication belongs in the security capability layer only after:

- credential source is defined
- request mutation model is defined
- secret handling policy is defined

---

## 12. Security Assertion Design

### Currently supported assertions

#### 1. HTTP assertion

Examples:

```text
with: status == 200
with: status != 500
```

AST:

- `ComparisonExpression`
- left: `status`
- right: `IntegerLiteral`

Validation:

- left is `status`
- right is an integer
- integer is a valid HTTP status code

Runtime evaluation:

- compare `response.status_code` to the expected value

Pass/fail behavior:

- pass if the condition holds
- fail otherwise

#### 2. Cloud property comparison

Example:

```text
with: public_access == false
```

AST:

- `ComparisonExpression` on property identifiers

Validation:

- property name is known
- type is acceptable

Runtime behavior:

- not implemented

#### 3. Expectation statements

Examples:

```text
expect: exists
expect: missing
```

AST:

- `ExpectationStatement(kind)`

Validation:

- kind is supported

Runtime behavior:

- not implemented

### Distinction

The project does not define a dedicated, separate "security assertion" runtime type distinct from HTTP assertions. The correct design does not invent one.

The current distinction is conceptual:

- HTTP assertion → implemented
- cloud/expectation/security-specific evaluation → under-defined or unimplemented

---

## 13. Request Mutation Design

### Current state

Request mutation is not implemented as a first-class concept.

The current engine:

- builds the URL
- calls the HTTP client
- captures the response

No mutation model exists for:

- original request immutability
- cloned/modified requests
- mutation records
- request builders
- payload application

### Recommended pattern

```text
Original Request
      ↓
Request Mutation
      ↓
Executable Request
      ↓
Web Execution Engine
      ↓
Response
```

### Best fit for the project

For future injection and authentication capabilities:

- keep the original request immutable
- create a modified/executable request separately
- execute the modified request
- keep original and modified request information separately in runtime context when needed
- record relevant mutation evidence in findings when needed

This avoids unexpected mutation of the original request.

---

## 14. Multiple Operation / Payload Execution

### Current state

The current AST enforces exactly one `RequestStatement` per `TestBlock`. This is a key constraint.

Therefore the project today does not define:

- multiple requests per test
- payload loops
- concurrency
- timeout per payload
- retries
- result aggregation across multiple requests

This is a **SPECIFICATION GAP**.

### Design implication

Any multi-payload execution must be added only after the AST and semantic validation are expanded.

The current project cannot support multiple request operations per test without changing the core grammar/AST contract.

Do not introduce loops or concurrency into the security layer as an implicit workaround.

---

## 15. Error and Failure Semantics

The project already differentiates among several runtime categories.

### Execution Error

**Definition**

Infrastructure failure or request transport failure.

**Examples**

- timeout
- connection failure
- HTTP client exception

**Current status**

- `ExecutionStatus.EXECUTION_ERROR`

### Assertion Failure

**Definition**

The request executed and a response was received, but the expected condition was not satisfied.

**Example**

- expected status `200`, actual `403`

**Current status**

- `ExecutionStatus.ASSERTION_FAILURE`

### Security Finding

**Definition**

A security capability detected a security-relevant observation or issue.

**Current status**

- not implemented

### Security Check Passed

**Definition**

A security capability executed/evaluated successfully and found no security issue for the defined check.

**Current status**

- not implemented

### Correct conceptual flow

These are not sequential failure states. They are distinct outcome dimensions:

```text
Execution
   ├── execution error
   └── response received
          ↓
       Assertion
       ├── pass
       └── failure
          ↓
    Security Evaluation
       ├── no finding
       ├── finding(s)
       └── inconclusive/error
```

A transport failure must not automatically become a security finding, and a successful HTTP response can still produce a security finding.

---

## 16. Security and Secret Handling

The current project does not define a complete secret-handling policy. The future design must account for:

- credentials
- API keys
- authorization headers
- tokens
- cookies
- payloads
- sensitive response bodies

### Design rules

- Never log raw credentials or tokens.
- Do not print full `Authorization` headers.
- Prefer redacted evidence in findings.
- Keep raw response content separate from sanitized evidence.
- Preserve only the minimum necessary request/response data in findings.
- Avoid persisting secrets in `SecurityFinding`.
- Define the secret source and lifecycle before implementing authentication.

These are required design rules even though they are not currently implemented.

---

## 17. Cloud Security

### Current status

Cloud security is **PARTIALLY DEFINED**.

The project defines:

- `TargetBlock(kind="cloud")`
- `ResourceStatement`
- `InspectionStatement`
- cloud property comparison semantics

But it does not define:

- provider runtime integration
- cloud credential source
- cloud inspection execution
- cloud result model
- cloud-specific finding semantics

### Conclusion

Cloud security is syntactically available but not runtime-implemented.

It is therefore a future capability, not current behavior.

### Design implication

Cloud capabilities should be added only after provider integration, credentials, inspection semantics, and result semantics are explicitly specified.

---

## 18. Proposed Package Structure

A minimal package layout consistent with the project is:

```text
cyberguard/
    security/
        __init__.py
        capability.py
        context.py
        finding.py
        result.py
        assertions.py
        injection.py
        detection.py
        auth.py
```

### Responsibilities

#### `capability.py`

- defines the security capability contract
- coordinates capability evaluation where required

#### `context.py`

- defines `SecurityContext`
- stores target/test/request/response/execution data

#### `finding.py`

- defines `SecurityFinding`
- stores security evidence and finding metadata

#### `result.py`

- defines `SecurityResult`
- aggregates findings and overall security outcome

#### `assertions.py`

- handles the existing HTTP status assertion
- provides a future home for additional assertion evaluation without changing the core parser/AST

#### `injection.py`

- future injection capability runtime
- request mutation only after mutation/payload semantics are specified

#### `detection.py`

- future response-detection capability

#### `auth.py`

- future authentication request preparation

This structure fits the existing project without requiring changes to the frozen core.

---

## 19. Test Strategy

### Unit Tests

- validation of comparison logic
- `SecurityFinding` creation
- `SecurityResult` creation and aggregation
- redaction rules
- context construction
- capability contract behavior
- request immutability for future mutation logic

### Execution Tests

- run capability logic against a fake HTTP client
- validate request and response behavior
- evaluate pass/fail semantics
- verify execution errors remain distinct from security findings

### Integration Tests

```text
DSL
  ↓
Parser
  ↓
Semantic Validation
  ↓
Validated AST
  ↓
Security / Execution Coordination
  ↓
Web Execution Engine
  ↓
Fake HTTP Client
  ↓
ExecutionResult
  ↓
Security Capability / Analysis
  ↓
Security Result / Finding
```

### Negative Tests

- invalid capability configuration
- unsupported injection kind
- invalid detection type
- missing request context
- invalid auth selector
- malformed finding data
- unsupported target state
- transport failure
- assertion failure
- security analysis with incomplete response data

### Constraint

Do not use real external targets in automated tests.

---

## 20. Specification Gaps

Only genuine gaps discovered from the current project state are listed below. These should be explicitly documented rather than guessed or filled with assumptions.

1. Injection payload definition is missing.
2. Injection request mutation rules are missing.
3. Detection semantics are missing.
4. Authentication credential source is undefined.
5. Security finding model is missing from the current implementation.
6. Security result/outcome model is missing from the current implementation.
7. Severity model is missing.
8. Evidence model is missing.
9. Request mutation model is missing.
10. Multiple payload execution is undefined.
11. Cloud runtime integration is missing.
12. Result aggregation rules are missing.
13. Secret handling policy is missing.
14. Authentication state/lifecycle across tests is undefined.
15. Expectation runtime semantics are missing.
16. Cloud provider/resource inspection semantics are missing.

These are specification or implementation gaps, not requirements that should be silently invented by the security layer.

---

## 21. Recommended Implementation Order

The implementation order should reflect dependencies and avoid modifying the frozen core.

### Phase 1: Security result model

- capability: `SecurityFinding` / `SecurityResult` model
- dependencies: existing runtime data only
- AST support: none
- runtime support: result classes only
- tests: unit tests
- complexity: low
- reason: foundation for all future security capabilities

### Phase 2: Security context and capability contract

- capability: `SecurityContext` + `SecurityCapability`
- dependencies: Phase 1
- AST support: none
- runtime support: context and capability interfaces
- tests: unit tests
- complexity: low
- reason: establishes the runtime boundary without changing the core

### Phase 3: HTTP assertion integration

- capability: existing status assertion behavior
- dependencies: existing Web Execution Engine + Phase 1/2 models
- AST support: existing `ComparisonExpression`
- runtime support: status evaluation
- tests: execution/integration tests
- complexity: low
- reason: validates the new security-layer boundary using already implemented behavior

### Phase 4: Detection capability

- capability: `detect: sql-error`
- dependencies: context + finding/result model + response analysis rules
- AST support: existing `DetectionStatement`
- runtime support: response inspection
- tests: fake response tests
- complexity: medium
- reason: clearest next capability from the current DSL once detection semantics are specified

### Phase 5: Injection capability

- capability: `inject: sql`
- dependencies: request mutation model + payload specification + finding/result model
- AST support: existing `InjectionStatement`
- runtime support: request mutation + response analysis
- tests: mutation/integration tests
- complexity: high
- reason: requires multiple currently missing specifications

### Phase 6: Authentication capability

- capability: authentication selectors
- dependencies: request mutation + credential source + secret policy
- AST support: existing `AuthenticationStatement`
- runtime support: header/cookie/token application
- tests: fake HTTP client authentication tests
- complexity: medium-high
- reason: requires credential-source and secret-handling definitions

### Phase 7: Expectation capability

- capability: expectation statements
- dependencies: explicit expectation runtime semantics
- AST support: existing `ExpectationStatement`
- runtime support: expectation evaluation
- tests: fake response/resource tests
- complexity: medium
- reason: the syntax and validation exist, but execution semantics are not yet defined

### Phase 8: Cloud security capability

- capability: cloud checks
- dependencies: provider integration + credential model + inspection semantics
- AST support: existing cloud AST
- runtime support: external cloud data access
- tests: cloud capability tests using mocks/fakes
- complexity: high
- reason: broadest and most undefined capability

---

## 22. Final Architecture Diagram

```text
CyberGuard Source
       ↓
     Lexer
       ↓
     Parser
       ↓
      AST
       ↓
Semantic Validation
       ↓
  Validated AST
       ↓
Security / Execution Coordination
       ↓
┌──────────────────────────────────────┐
│ Security Capabilities                │
│                                      │
│ Authentication preparation           │
│ Request mutation                     │
│ HTTP assertion evaluation            │
│ Response detection                   │
│ Expectation evaluation               │
│ Cloud property evaluation (future)   │
└──────────────────┬───────────────────┘
                   ↓
        Web Execution Engine
                   ↓
          ExecutionResult
                   ↓
          Security Analysis
                   ↓
           SecurityResult
                   ↓
       ┌───────────┴───────────┐
       ↓                       ↓
Security Finding(s)       No Finding
       ↓
 Future Reporter
```

This diagram preserves the actual architecture while correcting the execution ordering: request preparation/mutation occurs before HTTP transport, while response-based security analysis occurs after execution.

---

## 23. Design Decisions and Rationale

### 1. Keep the Web Execution Engine transport-oriented

- This aligns with the actual project architecture and frozen-core requirement.
- The engine already handles HTTP execution and response/status information.
- It should not absorb security capability logic.

### 2. Keep security capabilities thin

- Capabilities should operate on validated AST constructs and runtime context.
- They should not duplicate parser or semantic-validation responsibilities.

### 3. Do not place every capability after HTTP execution

- Authentication and injection may need to prepare or mutate the request before execution.
- Detection and response-based analysis operate after execution.
- The architecture therefore separates pre-execution capability work from post-execution analysis.

### 4. Avoid a generic "everything security" framework

- The project does not define enough runtime semantics to justify a broad abstraction.
- The design should be grounded in actual AST and validation support.

### 5. Treat security statements as partial until proven otherwise

- Authentication, injection, detection, expectations, and cloud checks are present, but their runtime semantics are incomplete.
- This should be documented explicitly instead of assumed.

### 6. Separate `ExecutionResult` from `SecurityFinding`

- A failed HTTP call is not the same as a security issue.
- A successful HTTP call can still produce a security finding.
- This separation is essential and justified by the current behavior.

### 7. Keep `SecurityFinding` and `SecurityResult` distinct

- A finding is an individual security observation.
- A result is the overall security evaluation that can contain zero or more findings.
- This avoids conflating evidence with aggregate status.

### 8. Preserve request immutability

- Future authentication and injection capabilities should operate on a separate executable/modified request.
- The original request should remain available for comparison and evidence.

### 9. Document missing requirements instead of inventing them

- The security layer is not yet fully specified.
- Genuine gaps must be called out explicitly.
- Unsupported payloads, credential flows, detection rules, or cloud behaviors must not be invented.

### 10. Preserve the stable core

- Lexer, Parser, AST, semantic validation, and the Web Execution Engine are treated as the stable architecture.
- The Security Capabilities phase should build on top of them rather than replace them.

---

## 24. Final Recommendation

The implementation-ready direction is:

```text
Frozen Core
    ↓
Validated AST
    ↓
Thin Security Capability Layer
    ↓
Web Execution Engine
    ↓
Security Analysis
    ↓
SecurityResult + SecurityFinding
```

The immediate implementation should focus on the **result model, context, and capability boundary**, followed by the already-proven HTTP assertion behavior. Detection, injection, authentication, expectations, and cloud security should be implemented only when their missing runtime semantics are explicitly specified.

This keeps CyberGuard grounded in its current implementation, avoids unsupported abstractions, preserves the stable core, and provides a controlled path toward a real security runtime.
