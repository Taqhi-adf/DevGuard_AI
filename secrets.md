# Secret Management

Never hard-code passwords, API keys, tokens or private credentials
inside source code.

Credentials must be stored in environment variables or a managed
secret-management system.

# SQL Injection

Applications must use parameterized SQL queries.

Never construct SQL statements by concatenating or interpolating
untrusted user input.

# Dynamic Code Execution

Avoid eval() and exec() when processing external or user-controlled
input.

Use explicit parsers and allowlisted operations.

# Error Handling

Do not silently swallow exceptions.

Catch specific exceptions and record useful diagnostic information
without exposing secrets or personal data.

# Testing

Security-sensitive functions must have tests for:

- normal input
- invalid input
- malicious input
- regression cases