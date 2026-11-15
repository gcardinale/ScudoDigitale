# Contributing to Scudo Digitale

Thank you! Before opening a pull request:

1. **Mandatory header** — every `.cs` file starts with the box from [`build/header.txt`](build/header.txt). CI fails if it is missing. Do not remove or alter it: it is a license term (AGPL section 7(b), see [NOTICE](NOTICE)).
2. **XML documentation** on all public and protected members (`CS1591` is a compile error). XML docs and identifiers are written in English.
3. **Tests** — minimum **90%** line and branch coverage: `dotnet test` fails below it (see `tests/Directory.Build.targets`). A test project for a module with no code yet carries `<ModuleNotStarted>true</ModuleNotStarted>`, which switches the gate off: the build fails as soon as the module or its test project contains a C# file, so remove the flag together with the first code. Test names: `Method_WhenCondition_ShouldExpectedResult`. No real network in tests: use the in-process fake servers.
4. **New checks** — implement `ICheck` and declare area, prerequisites and `ScopeRequirement`. An **active** check must never run without `IScopeGuard` (see [ADR-004](docs/decisions/ADR-004-passive-vs-active-scope.md)).
5. **User-facing strings** go in `.resx` resource files, in English and Italian (Italian is selected automatically when the OS language is Italian).
6. **Never** write code that attempts logins, bruteforce, vulnerability exploitation, Wi-Fi deauthentication or forced Bluetooth pairing.
7. **Commits** that explain the *why*. By contributing you agree that your code is distributed under the same license (AGPL-3.0-or-later + additional terms).
