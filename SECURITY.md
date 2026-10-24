# Security Policy

## Scope

JOSEKit creates and verifies signed and encrypted tokens, so a flaw in it can let a forged
token through or expose what a token protects. Treat as security issues, for example: a token
accepted that should be refused, an algorithm or key confused with another, a key or plaintext
leaked through errors or timing, unbounded resource use driven by a token, and anything in
[DESIGN.md](DESIGN.md) section 2 that turns out not to hold.

What JOSEKit deliberately does not do yet is listed in [TODO.md](TODO.md); a gap listed there is
not a vulnerability, though a report that it matters more than we thought is welcome.

## Supported versions

JOSEKit has not had a release yet. Fixes go to `main`. Once releases begin, only the latest
receives security fixes until 1.0.

## Reporting a vulnerability

Please **do not** report security issues through public GitHub issues.

Instead, either:

- Use GitHub's private vulnerability reporting on the
  [Security tab](https://github.com/AlexNachbaur/JOSEKit/security) of the repository, or
- Email <alex@nachbaur.com> with a description of the issue, steps to reproduce, and the commit
  or version affected.

Never include real private keys or live tokens in a report; generate throwaway ones.

You can expect an acknowledgment within a few days. Please allow a reasonable window for a fix
to be released before disclosing publicly.
