# Project coding rules
Priority: this file > the author's general conventions > native C# conventions.

- Modern C#: file-scoped namespaces, `nullable enable`, `TreatWarningsAsErrors` on, `async` all the way down with a `CancellationToken` on every network operation.
- `build/header.txt` header on every `.cs`, before any `using`.
- XML docs on all public/protected members, in **English**. Identifiers in **English** (.NET convention).
- User-facing strings are localized through resource files (`.resx`) with **English and Italian**; Italian is chosen automatically when the OS language is Italian, English otherwise.
- Tests: `Method_WhenCondition_ShouldExpectedResult`; no real network (fake in-process DNS/HTTP/TLS servers, sample files in `tests/**/Fixtures`).
- Every check has a stable id `AREA-TOPIC-NNN` (e.g. `MAIL-DMARC-001`), never reused; the risk and fix text lives in the catalog, not in the detection code.
- Timeouts and concurrency are always configurable; cautious defaults (e.g. 50 simultaneous TCP connections, 2 s timeout).
- No `Process.Start` with unvalidated user input; system commands only with argument lists.
- No secrets in code; the optional HIBP key is read from an environment variable or from the OS protected store.
