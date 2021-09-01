# `toutoumomoma`

`toutoumomoma` provides functions that may help you to answer the question of an executable, “是偷偷摸摸吗？”

- `Stripped`: scan files that may be executable and report whether they are a Go executable that has had its symbols stripped.
- `ImportHash`: calculate the [imphash](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html) of an executable with dynamic imports.
- `GoSymbolHash`: calculate an imphash analogue for Go executables compiled by the gc-compiler.
- `Sections`: provide section size statistics for an executable.
