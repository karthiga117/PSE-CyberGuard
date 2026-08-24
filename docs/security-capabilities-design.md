# CyberGuard Security Capabilities Design

## 1. Executive Summary

CyberGuard’s current implementation is a layered system with a stable core:

- Lexer
- Parser
- AST
- Semantic Validation
- Web Execution Engine v0.1

The project currently contains a small but real set of security-oriented constructs, but it does not yet define a complete security runtime. The present state is best described as:

- some security semantics are expressed in the DSL and AST,
- semantic validation enforces a subset of them,
- the Web Execution Engine executes HTTP requests and status assertions,
- the actual security capability layer is still partial or undefined.

The most important architectural fact is that the project already distinguishes between:

- ExecutionResult: execution- and transport-oriented outcomes
- security intent: capability-specific outcomes that are not yet modeled as a first-class runtime object

The correct Security Capabilities design is therefore a thin layer above the validated AST and the existing Web Execution Engine, not a redesign of the stable core. It must reuse established project semantics and avoid inventing unsupported DSL syntax, AST nodes, or runtime behaviors.

Important project realities:

- The DSL does not currently define target URL syntax; the runtime target URL is supplied externally in tests.
- The parser and AST do include RequestStatement.path, but the current runtime path handling is limited to URL concatenation.
- Authentication, injection, detection, and expectations exist as syntax/validation constructs, but their runtime behavior is not implemented.
- Security findings and security result objects are NOT CURRENTLY DEFINED.

This therefore becomes a minimal and grounded architecture centered on:

- validated AST
- Web Execution Engine
- SecurityCapability abstraction
- SecurityContext
- SecurityFinding / SecurityResult separation

No generic security framework should be assumed.

## 2. Current Security Capabilities

| Capability | DSL Representation | AST Representation | Semantic Validation | Runtime Requirement | Current Status |
| --- | --- | --- | --- | --- | --- |
| HTTP request execution | request: GET / POST / PUT / DELETE / PATCH / HEAD / OPTIONS | RequestStatement(method, path?) | Validates method and optional path format | Execute HTTP request via Web Execution Engine | CURRENTLY DEFINED |
| Status assertion | with: status == 200 / with: status != 500 | ComparisonExpression(left=status, operator, right=IntegerLiteral) | Validates status is integer and valid HTTP code | Compare response status against expected value | CURRENTLY DEFINED |
| Authentication selector | authenticate: basic / bearer / api-key / cookie | AuthenticationStatement(method) | Validates supported methods | Apply auth metadata to request | PARTIALLY DEFINED |
| Injection intent | inject: sql | InjectionStatement(kind="sql") | Validates kind is supported | Mutate request and analyze response | PARTIALLY DEFINED |
| Detection intent | detect: sql-error | DetectionStatement(kind="sql-error") | Validates kind is supported | Inspect response for detection pattern | PARTIALLY DEFINED |
| Expectation semantics | expect: exists / missing / contains / not-contains / not-exists / enabled / disabled | ExpectationStatement(kind) | Validates supported kinds | Evaluate requested expectation behavior | PARTIALLY DEFINED |
| Cloud property checks | with: public_access == false | ComparisonExpression on cloud property names | Validates supported cloud properties and scalar rules | Evaluate cloud property checks | PARTIALLY DEFINED |
| Target URL handling | not parsed by DSL today | TargetBlock.url | URL validity check | Build final request URL | PARTIALLY DEFINED |
| Request path concatenation | request path is optional in request syntax | RequestStatement.path | path must begin with "/" if present | Combine base target URL with request path | PARTIALLY DEFINED |
| Security finding model | Not defined in DSL | Not defined in AST | No semantic rule exists | No finding model today | NOT CURRENTLY DEFINED |

### Capability-by-capability meaning

1. HTTP Request Execution
   - The web target is request-driven.
   - A request test is built around a RequestStatement plus optional evaluation.
   - The current runtime sends an HTTP request to a target URL and captures the response.

2. Status Assertion
   - This is the proven, implemented assertion.
   - It uses a ComparisonExpression against response status.
   - This is the only fully realized runtime assertion in the current project.

3. Authentication Selection
   - The DSL supports:
     - basic
     - bearer
     - api-key
     - cookie
   - The AST stores only the method string.
   - No runtime behavior converts that selector into request headers, cookies, or token handling.

4. Injection Intent
   - The DSL contains inject: sql.
   - Semantic validation recognizes only sql.
   - No payload model or request mutation flow exists.

5. Detection Intent
   - The DSL contains detect: sql-error.
   - Semantic validation recognizes only sql-error.
   - No response analysis engine exists.

6. Expectation Statements
   - The AST includes ExpectationStatement(kind),
   - Validation recognizes the supported expectation kinds,
   - But runtime semantics are not implemented.

7. Cloud Property Checks
   - Cloud targets and property comparisons are semantically defined.
   - Yet the current project does not implement a cloud runtime.

8. Target URL Handling
   - Current tests override TargetBlock.url after parsing.
   - This indicates URL syntax is not currently parsed by the DSL.
   - The runtime engine still consumes target URL when supplied.

9. Request Path Handling
   - RequestStatement.path exists and is semantically validated.
   - When present, the engine combines base URL + path to construct the final request URL.

10. Security Finding Model
   - This is explicitly NOT CURRENTLY DEFINED.
   - There is no SecurityFinding or SecurityResult object in the actual codebase.

## 3. DSL → AST → Semantic → Runtime Mapping

### Core mapping

DSL
 ↓
AST
 ↓
Semantic Validation
 ↓
Security Capability
 ↓
Runtime Behavior
 ↓
Security Result

### Mapping examples

#### A. Request + status check

DSL:

- target: web
- test: request
- request: GET
- with: status == 200

AST:

- TargetBlock
- TestBlock
- RequestStatement(method="GET", path?)
- WithStatement(expression=ComparisonExpression(...status...))

Semantic validation:

- HTTP method allowed
- status comparison valid
- integer uses valid status range
- request path valid if set

Runtime behavior:

- build URL
- send HTTP request
- evaluate status

Result:

- ExecutionResult.SUCCESS or ASSERTION_FAILURE

#### B. Authentication

DSL:

- authenticate: bearer

AST:

- AuthenticationStatement(method="bearer")

Semantic validation:

- method is supported

Runtime behavior:

- currently NONE

Result:

- no security result exists

#### C. Injection

DSL:

- inject: sql

AST:

- InjectionStatement(kind="sql")

Semantic validation:

- kind is supported

Runtime behavior:

- not implemented

Result:

- no security result exists

#### D. Detection

DSL:

- detect: sql-error

AST:

- DetectionStatement(kind="sql-error")

Semantic validation:

- kind is supported

Runtime behavior:

- not implemented

Result:

- no security result exists

#### E. Cloud property check

DSL:

- with: public_access == false

AST:

- ComparisonExpression(left=IdentifierValue("public_access"), ...)

Semantic validation:

- known cloud property
- valid scalar type

Runtime behavior:

- not implemented

Result:

- no security result exists

## 4. Security Runtime Architecture

The architecture should be thin and grounded in the actual project:

Validated AST
     ↓
Web Execution Engine
     ↓
Security Capability
     ↓
Security Analysis
     ↓
Security Result / Finding

This is the minimal, justified shape. It preserves the existing execution engine while creating a dedicated security layer above it.

### Boundaries

1. Validated AST
   - Semantic validation guarantees all structural and semantic rules have already passed.
   - The runtime can safely assume:
     - supported methods
     - valid request paths
     - valid comparison shape
     - valid injection/detection kind
     - valid cloud properties
     - valid target URL if present

2. Web Execution Engine
   - This remains HTTP transport-only.
   - It builds URLs, executes requests, and returns ExecutionResult.
   - It must not become the security engine.

3. Security Capability
   - A capability handles one validated security concern.
   - It may:
     - evaluate a status assertion,
     - apply auth,
     - mutate a request,
     - analyze a response for a known issue,
     - produce a finding.

4. Security Analysis
   - Converts execution data into security meaning.
   - Example:
     - request succeeded
     - response indicates a security concern
     - capability found evidence
     - expected vs actual mismatch

5. Security Result / Finding
   - A future model for security-specific conclusions.
   - Distinct from ExecutionResult.

### Minimum justified abstractions

#### SecurityCapability

Responsibility:

- execute a single security concern over a validated AST node and runtime context

Inputs:

- validated AST item
- SecurityContext

Outputs:

- SecurityResult or SecurityFinding

Dependencies:

- ExecutionEngine
- SecurityContext

Why required:

- The current project already mixes multiple security concerns into the AST and semantic validation, but the execution layer is not structured for them.

Why not combine:

- The execution engine must remain transport-focused.

#### SecurityContext

Responsibility:

- carry the minimal runtime data needed by a security capability

Inputs:

- target
- test
- request
- response
- optional mutation state
- optional prior findings

Outputs:

- uniform runtime context

Why required:

- security logic needs data beyond the raw execution result

Why not combine:

- it should not be the engine itself

#### SecurityFinding

Responsibility:

- represent a security-relevant issue or a check result

Inputs:

- capability
- evidence
- target/test metadata
- request/response evidence

Outputs:

- structured finding object

Dependencies:

- SecurityContext

Why required:

- security issues are not the same as execution failure

Why not combine:

- transport status is not equivalent to vulnerability detection

#### SecurityResult

Responsibility:

- aggregate one or more findings

Inputs:

- list of findings
- overall evaluation state

Outputs:

- security result summary

Why required:

- capabilities can yield many findings or a pass result

Why not combine:

- execution results should remain separate

### Abstractions not justified

- DetectionEngine
- InjectionExecutor
- AuthenticationStrategy
- broad plugin architecture
- large reporting framework

These are not supported by the current project state and should not be introduced without explicit requirements.

## 5. Security Capability Interfaces

The recommended capability contract is intentionally narrow:

- evaluate(validated_ast_node, context) -> SecurityResult
- or create_finding(...) -> SecurityFinding

This keeps the layer simple and aligned with current project structure.

### Capability categories

1. HTTP assertion capability
   - already present in project semantics
   - evaluates status comparison

2. Injection capability
   - future capability
   - works from InjectionStatement

3. Detection capability
   - future capability
   - works from DetectionStatement

4. Authentication capability
   - future capability
   - works from AuthenticationStatement

5. Cloud security capability
   - future capability
   - works from cloud target properties and resource/inspection semantics

### Design rule

Each capability should be scoped to one security intent and should not manage:

- parsing
- validation
- HTTP transport
- reporting
- persistence

## 6. Security Context

The current project does not define a giant runtime object. A minimal context is sufficient.

Recommended SecurityContext fields:

Required:

- target
- test
- request
- response
- capability
- original_request
- findings

Optional:

- modified_request
- payload
- auth_state
- previous_results
- variables

### Why this is sufficient

The current runtime is fundamentally request/response-driven. The security layer needs:

- target being tested
- request used
- response captured
- command/test origin
- optional mutation details

There is no evidence in the project that a large generic context object is required.

## 7. Security Result and Finding Model

This is a critical design boundary.

### ExecutionResult

Current meaning:

- runtime request succeeded or failed
- assertion passed or failed
- execution error occurred

Examples:

- HTTP timeout -> EXECUTION_ERROR
- status mismatch -> ASSERTION_FAILURE
- status match -> SUCCESS

### SecurityFinding

A security finding represents that a capability observed a security-relevant issue or check result.

Examples:

- request returned an error page with SQL error pattern
- candidate injection payload produced a response indicating possible weakness
- auth selector exists but no credential source is defined yet

### Recommended relationship

ExecutionResult
- transport/execution result

SecurityFinding
- security interpretation

SecurityResult
- container for one or more findings

### Recommended SecurityFinding fields

Required:

- capability
- target
- test
- request
- response
- evidence
- outcome

Optional:

- rule
- severity
- title
- description
- expected
- actual
- remediation

Future:

- cwe
- confidence
- compliance tag
- report metadata

### Why these fields are required

- capability: what evaluated the issue
- target: what was assessed
- test: which test block produced it
- request: what request triggered the result
- response: what evidence was observed
- evidence: what justifies the issue
- outcome: whether the check passed, failed, or was inconclusive

### Decision

SecurityFinding should be a separate result object, not embedded inside ExecutionResult. A SecurityResult wrapper can then aggregate one or more findings.

## 8. Injection Design

### Current status

Injection is PARTIALLY DEFINED.

The project currently defines:

- InjectionStatement(kind="sql")
- semantic validation supports sql
- no runtime injection behavior exists

This means:

- Injection is NOT CURRENTLY IMPLEMENTED as a real runtime capability.

### Current mapping

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

### Actual missing requirements

The project does not define:

- payload source
- payload representation
- injection position
- request mutation rules
- multi-payload behavior
- detection criteria for SQL-error responses

These are SPECIFICATION GAPS.

### Design recommendation

Until these are specified, injection should remain a future capability that builds on:

- validated InjectionStatement
- request mutation semantics
- SecurityContext
- SecurityFinding

No payloads or syntax should be invented based on assumption.

## 9. Detection Design

### Current status

Detection is PARTIALLY DEFINED.

Current AST:

- DetectionStatement(kind="sql-error")

Semantic validation:

- accepts only sql-error

Current runtime:

- none

### Minimal runtime flow

Response
   ↓
Detection
   ↓
Detection Result
   ↓
Security Finding

### Missing requirements

The project does not define:

- which response fields are inspected
- exact detection logic
- pass/fail semantics
- result model for detection
- relationship between detection and vulnerability finding

This is a SPECIFICATION GAP.

### Recommendation

Detection should be implemented as a future capability once response analysis rules are specified. The design should reuse the same SecurityContext and SecurityFinding model.

## 10. Authentication Design

### Current status

Authentication is PARTIALLY DEFINED.

Supported methods:

- basic
- bearer
- api-key
- cookie

AST:

- AuthenticationStatement(method)

Validation:

- method must be recognized

Runtime behavior:

- NONE

### Missing requirements

The project does not define:

- credential source
- token or cookie creation
- header construction
- request mutation behavior
- state across tests

### Conclusion

Authentication is PARTIALLY DEFINED but runtime behavior is NOT CURRENTLY DEFINED.

It should not be integrated into the current Web Execution Engine.

### Recommended placement

Authentication belongs in a future capability layer only after:

- credential source is defined
- request mutation model is defined
- secret handling policy is defined

## 11. Security Assertion Design

### Currently supported assertions

1. HTTP assertion
   - with: status == 200
   - with: status != 500

AST:

- ComparisonExpression
- left: status
- right: IntegerLiteral

Validation:

- left is status
- right is integer
- integer is valid HTTP status code

Runtime evaluation:

- compare response.status_code to expected value

Pass/fail behavior:

- pass if condition holds
- fail otherwise

2. Cloud property comparison
   - with: public_access == false
   - etc.

AST:

- ComparisonExpression on property identifiers

Validation:

- property name known
- type acceptable

Runtime behavior:

- not implemented

3. Expectation statements
   - expect: exists
   - expect: missing
   - etc.

AST:

- ExpectationStatement(kind)

Validation:

- kind supported

Runtime behavior:

- not implemented

### Distinction

The project does not define a dedicated, separate “security assertion” runtime type distinct from HTTP assertions. The correct design does not invent one. The current distinction is conceptual:

- HTTP assertion = implemented
- security assertion = currently under-defined or unimplemented

## 12. Request Mutation Design

### Current state

Request mutation is not implemented as a first-class concept.

The current engine:

- builds URL
- calls HttpClient.request
- captures response

But no mutation model exists for:

- original request immutability
- cloned requests
- mutation records
- request builders

### Recommended pattern

Original Request
      ↓
Request Mutation
      ↓
Executable Request

### Best fit for the project

For future injection and auth capabilities:

- keep original request immutable
- create a modified request object separately
- execute the modified request
- keep both original and modified request in the runtime context
- record mutation in findings when needed

This is consistent with the current architecture and avoids mutating the original request unexpectedly.

## 13. Multiple Operation / Payload Execution

### Current state

The current AST enforces exactly one RequestStatement per TestBlock. This is a key constraint.

Therefore the project today does not define:

- multiple requests per test
- payload loops
- concurrency
- timeout per payload
- retries
- result aggregation across multiple requests

This is a SPECIFICATION GAP.

### Design implication

Any multi-payload execution must be added only after the AST and semantic validation are expanded. The current project cannot support it without changing the core grammar.

## 14. Error and Failure Semantics

The project already differentiates among several runtime categories.

### Execution Error

Definition:

- infrastructure failure or request transport failure

Examples:

- timeout
- connection failure
- HttpClient exception

Current status:

- ExecutionStatus.EXECUTION_ERROR

### Assertion Failure

Definition:

- request executed, response received, but expected condition was not satisfied

Example:

- expected status 200, actual 403

Current status:

- ExecutionStatus.ASSERTION_FAILURE

### Security Finding

Definition:

- a capability detected a security-relevant issue or risk

Current status:

- not implemented

### Security Check Passed

Definition:

- capability executed successfully and found no issue

Current status:

- not implemented

### Correct conceptual flow

Execution error
↓
Assertion failure
↓
Security finding
↓
Security check passed

These must remain distinct categories. Security findings should not be collapsed into execution or assertion failure semantics.

## 15. Security and Secret Handling

The current project does not define a security secret-handling policy. The future design must still account for:

- credentials
- API keys
- authorization headers
- tokens
- cookies
- payloads
- sensitive response bodies

### Design rules

- Never log raw credentials or tokens
- Do not print full Authorization headers
- Prefer redacted evidence in findings
- Keep raw response content separate from sanitized evidence
- Preserve only the minimum necessary request/response data in findings

This is a required design rule even though it is not currently implemented.

## 16. Cloud Security

### Current status

Cloud security is PARTIALLY DEFINED.

The project defines:

- TargetBlock(kind="cloud")
- ResourceStatement
- InspectionStatement
- cloud property comparison semantics

But it does not define:

- provider runtime integration
- cloud credential source
- cloud inspection execution
- cloud result model
- cloud-specific findings

### Conclusion

Cloud security is syntactically available but not runtime-implemented. It is therefore a future capability, not current behavior.

## 17. Proposed Package Structure

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

#### capability.py

- defines security capability interfaces
- orchestrates capability evaluation

#### context.py

- defines SecurityContext
- stores target/test/request/response data

#### finding.py

- defines SecurityFinding
- stores evidence and findings metadata

#### result.py

- defines SecurityResult
- aggregates multiple findings

#### assertions.py

- handles HTTP status assertion and future security assertion logic

#### injection.py

- future injection capability runtime

#### detection.py

- future response-detection logic

#### auth.py

- future authentication request behavior

This structure fits the existing project without modifying frozen architecture.

## 18. Test Strategy

### Unit Tests

- validation of comparison logic
- result object creation
- redaction rules
- context construction
- capability interface behavior

### Execution Tests

- run capability logic against fake HTTP client
- validate request and response behavior
- evaluate pass/fail semantics

### Integration Tests

DSL
 ↓
Parser
 ↓
Semantic Validation
 ↓
Execution Engine
 ↓
Security Capability
 ↓
Fake HTTP Client
 ↓
Security Result / Finding

### Negative Tests

- invalid capability config
- unsupported injection kind
- invalid detection type
- missing request context
- invalid auth selector
- malformed findings
- unsupported target state

### Constraint

Do not use real external targets.

## 19. Specification Gaps

# Specification Gaps

1. Injection payload definition is missing.
2. Injection request mutation rules are missing.
3. Detection semantics are missing.
4. Authentication credential source is undefined.
5. Security finding model is missing.
6. Severity model is missing.
7. Evidence model is missing.
8. Request mutation model is missing.
9. Multiple payload execution is undefined.
10. Cloud runtime integration is missing.
11. Result aggregation rules are missing.
12. Secret handling policy is missing.

These are genuine gaps in the current spec and should be explicitly documented rather than guessed.

## 20. Recommended Implementation Order

### Phase 1: Security result model

- capability: finding/result model
- dependencies: none beyond existing runtime data
- AST support: none
- runtime support: result classes only
- tests: unit tests
- complexity: low
- reason: foundation for all security capabilities

### Phase 2: HTTP assertion semantics hardening

- capability: status comparison evaluation
- dependencies: ExecutionEngine
- AST support: ComparisonExpression
- runtime support: final pass/fail classification
- tests: fake HTTP client execution tests
- complexity: low
- reason: current implementation already exists

### Phase 3: security capability abstraction

- capability: common capability wrapper
- dependencies: result model and context model
- AST support: current set
- runtime support: capability interface
- tests: capability unit/integration tests
- complexity: low-medium
- reason: simplifies future capability implementation

### Phase 4: detection capability

- capability: detect: sql-error
- dependencies: context + finding model + response analysis
- AST support: DetectionStatement
- runtime support: response inspection
- tests: fake response tests
- complexity: medium
- reason: it is the clearest next capability from current DSL

### Phase 5: injection capability

- capability: inject: sql
- dependencies: request mutation model, finding model
- AST support: InjectionStatement
- runtime support: request mutation + response analysis
- tests: mutation/integration tests
- complexity: high
- reason: requires missing payload and mutation semantics

### Phase 6: authentication capability

- capability: auth selectors
- dependencies: request mutation + secret policy
- AST support: AuthenticationStatement
- runtime support: header/cookie/token application
- tests: fake HTTP client auth tests
- complexity: medium-high
- reason: requires credential source definition

### Phase 7: cloud security capability

- capability: cloud checks
- dependencies: provider integration
- AST support: cloud AST
- runtime support: external cloud data access
- tests: cloud capability tests
- complexity: high
- reason: broadest and most undefined capability

## 21. Final Architecture Diagram

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
Web Execution Engine
       ↓
Security Capability
       ↓
┌────────────────────────────┐
│ Security Operation         │
│ Request evaluation         │
│ Response inspection        │
│ Assertion evaluation       │
│ Future request mutation    │
│ Future detection logic     │
└──────────────┬─────────────┘
               ↓
        Security Result
               ↓
        Security Finding
               ↓
           Future Reporter
```

This diagram preserves the actual architecture while making room for security-specific logic that sits above the execution transport layer.

## 22. Design Decisions and Rationale

1. Keep the Web Execution Engine transport-only
   - This aligns with the actual project architecture and the frozen core requirement.
   - The engine already handles HTTP execution and status evaluation.
   - It should not absorb security capability logic.

2. Avoid a generic “everything security” framework
   - The project does not define enough runtime semantics to justify a broad abstraction.
   - The design must be grounded in actual AST and validation support.

3. Treat security statements as partial until proven otherwise
   - Authentication, injection, detection, and cloud checks are present, but not complete.
   - This should be documented explicitly instead of assumed.

4. Separate ExecutionResult from SecurityFinding
   - A failed HTTP call is not the same as a security issue.
   - A successful HTTP call can still have a security finding.
   - This separation is essential and justified by current behavior.

5. Keep the security layer thin and validated-AST-driven
   - This matches the organization of the project.
   - It prevents unnecessary redesign while enabling future extension.

6. Document missing requirements instead of inventing them
   - The security layer is not yet fully specified.
   - The design must call out genuine gaps and avoid assumption-filled implementations.

7. Preserve the stable core
   - Lexer, Parser, AST, semantic validation, and the execution engine are all effectively frozen.
   - The security capabilities phase should build on top of them rather than replace them.

This is the correct implementation-ready design for the next Security Capabilities phase: grounded, minimal, and consistent with the actual CyberGuard project.
