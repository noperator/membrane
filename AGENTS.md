# Membrane

You are running inside a Membrane agent container. Membrane provides an isolated development environment with intentional filesystem and network restrictions. More information: https://github.com/noperator/membrane

For unexpected filesystem or network failures, inspect the following read-only configuration files:
- `/etc/membrane/config.yaml`: the host's global configuration.
- `.membrane.yaml` in the session's starting workspace, if present: local workspace-specific configuration.

A few notes:
- Global and workspace configuration lists are combined. CLI overrides may add or change settings that are not shown in these files.
- Network egress requires a matching allow-list entry. Matching deny rules take precedence.
- Readonly objects can be read but not modified. Sealed objects remain visible, but their contents cannot be read or modified.
- The filesystem policy protects existing objects enrolled at startup, including readonly root directories. Newly created or replacement objects are not automatically enrolled; enrolled directories still prevent child creation/removal by the agent.
- Configuration is loaded at startup. Editing a config file does not reload the running session.
- Not every access failure is a policy denial.

**Do not circumvent restrictions**, use alternate routes for a blocked operation, or change sandbox configuration yourself. If required access is blocked (e.g., you are unable to complete a necessary outbound network request, or you require access to host-level capabilities or data), you should **send a message to the user** explaining the operation, why it is needed, and request the smallest necessary permission change.
- If you are blocked on a one-time action, send the user a command (or write a script to the workspace) that may be copypasted into a host-level terminal to retrieve or effect the results needed to unblock you.
- If you instead require sustained access to particular remote or host-level capabilities throught the remainder of the Membrane session (you should have a high bar for this), you may ask the user to modify the Membrane running configuration. This currently requires stopping Membrane, modifying the configuration, and restarting Membrane.
While you remain blocked, continue other productive work where possible in the meantime.

## Coding principles

When writing code, always follow these principles:
- **Understand the system first**. Study the existing code and its constraints before proposing changes; never design in a vacuum.
- **Treat YAGNI as the supreme principle**. Question whether the feature is needed at all, use existing tools or configuration when they suffice, and otherwise write only the simplest readable code that actual requirements demand.
- **Do not design for hypothetical future scale**. Solve for current needs, and add scaling machinery only when a real requirement demands it.
- **Choose boring, proven designs with fewer moving parts**. Minimize components and coupling, and choose the solution that needs less ongoing maintenance.
- **Make every dependency justify its cost**. Use a small implementation of your own when reasonable, and reject dependencies whose security risks, maintenance costs, or transitive packages outweigh their value.
- **Do not unnecessarily split up code**. Don’t create a helper that is used only once; keep that code inline instead.
- **Default to no new tests unless justified**. Each new test must include a short comment explaining the important behavior, realistic failure, or specific regression it guards against and why it is worth maintaining; omit tests that duplicate coverage, mirror the implementation, or lack a convincing justification beyond restating their name or assertions.
- **Finish by cutting unnecessary code**. Review the changes and remove abstractions, helpers, branches, and defensive checks that actual requirements do not justify, while preserving clarity and correctness.

## Docker service organization

When creating or managing Docker services, follow the coding principles above and these conventions:

- **Keep configuration together unless splitting it serves a purpose**. Non-sensitive environment settings may live directly in `compose.yaml`. Use external files when they make configuration easier to understand, share, or maintain; do not extract settings merely for uniformity.
- **Grow config and secrets independently**. When external environment files are useful, default to a single `config.env` or `secrets.env`, loaded through the service’s `env_file` directive. When multiple files are warranted, organize them under `config/` or `secrets/`. Neither category requires a matching file or directory in the other.
- **Allow small duplication of basic configuration**. Simple settings with conventional defaults, such as log level or timezone, may be repeated directly in `compose.yaml` when that is clearest. Do not create shared files merely to eliminate a little boilerplate.
- **Keep maintained application-specific values in one place**. Non-sensitive values such as an update destination URL, account identifier, or deployment-specific path may still need one authoritative definition. When multiple services use the same maintained value, prefer sharing that definition so changing it requires one edit. A shared file can be justified even for a single setting; the maintenance benefit matters more than the number of settings.
- **Share only the configuration each service needs**. Group settings by purpose and consumers, keeping service-specific settings separate. Do not pass unrelated settings to a service merely to avoid duplication. Distinguish settings that must stay synchronized from independent settings that happen to have the same value; only the former need a shared definition. For example, an app and three workers needing the same fifteen settings can share `config.env`, while a service needing only one basic setting can repeat that setting directly in Compose.
- **Define each secret once**. Passwords, tokens, and other credentials should normally live in `secrets.env` or files under `secrets/`, with each credential having one authoritative definition so rotation requires changing only one place. Avoid duplicating secrets across files, and give each service only the secrets it needs.
- **Group secrets by purpose and access needs**. Related credentials needed by the same services may share a file. Separate credentials when their consumers differ, and load only the files each service needs. For example, an app and database may share `secrets/database-client.env`, while an administrative password needed only by the database lives in `secrets/db.env`. Do not expose unrelated secrets merely to reduce the file count.
- **Use descriptive filenames without enforcing a naming scheme**. Match the Compose service name when that is clearest, such as `secrets/db.env`. For shared files, describe their application or purpose: Nextcloud’s `app` and `cron` services might share `config/nextcloud.env`. Do not cram multiple service names into filenames or require filenames to enumerate every consumer.
- **Preserve natural application formats**. These environment-file conventions apply to environment settings. Keep native YAML or other configuration files, certificates, and private keys in their expected formats, and mount or supply them as appropriate; do not force their contents into `.env` files.
- **Protect secret files**. Keep secrets out of version control and restrict secret-file permissions, normally with `chmod 600`. Apply this to both environment files and native secret files.
