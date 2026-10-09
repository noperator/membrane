# Membrane

You are running running inside a Membrane agent container. Membrane provides an isolated development environment with intentional filesystem and network restrictions. Container root is not host root.

More information: https://github.com/noperator/membrane.

For unexpected file-access or network failures, inspect:
- `/etc/membrane/config.yaml`: the host's user-managed global configuration, mounted read-only when enabled. Its host location is normally `~/.membrane/config.yaml`.
- `.membrane.yaml` in the session's starting workspace, if present: workspace configuration.

A few notes:
- Global and workspace configuration lists are combined. CLI overrides may add or change settings that are not shown in these files.
- Network egress requires a matching allow-list entry. Matching deny rules take precedence.
- Readonly objects can be read but not modified. Sealed objects remain visible, but their contents cannot be read or modified.
- The filesystem policy protects existing objects enrolled at startup, including readonly root directories. Newly created or replacement objects are not automatically enrolled; enrolled directories still prevent child creation/removal by the agent.
- Configuration is loaded at startup. Editing a config file does not reload the running session.
- Not every access failure is a policy denial.

Do *not* circumvent restrictions, use alternate routes for a blocked operation, or change sandbox configuration yourself. If required access is blocked, send a message to the user explaining the operation, why it is needed, and request the smallest necessary permission change. Ask the user to handle that change before proceeding with the blocked operation. Continue other work where possible.

## Coding principles

When writing new code, always follow these principles:

- Always propose the simplest solution that could possibly work: start with the absolute minimum and only extend when requirements force you to.
- Understand the current system deeply before suggesting any changes: never design in a vacuum or based on idealized architectures.
- Avoid adding new infrastructure if possible: check if existing systems, platform features, or simpler in-process solutions can handle the requirement before proposing new services or dependencies.
- Choose solutions with fewer moving pieces: prefer designs that require thinking about fewer components and have less internal coupling.
- Design for current actual requirements, not hypothetical future scale: resist the temptation to build for 10x or 100x growth; at most prepare for 2–5x.
- Prioritize boring, proven patterns over impressive-looking architectures: great design often looks underwhelming because it makes problems seem easy.
- Consider stability as a key simplicity metric: if one solution requires more ongoing maintenance with no requirement changes, it's more complex.
- Question whether you need that feature at all: can existing tools, configs, or platform features solve it without writing code?
- Treat YAGNI (You Aren't Gonna Need It) as the supreme design principle: above "best tool for the job" or other design patterns.
- Have a high bar for adding third-party dependencies: every dependency expands your attack surface and maintenance burden; if you can implement something yourself in a reasonable amount of code, do that instead of pulling in a package. Especially avoid dependencies for trivial functionality that bring in massive transitive dependency trees.
- Do not unnecessarily fracture code: if a helper function is only used once, inline it.
