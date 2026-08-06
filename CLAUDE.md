# Claude Code Project Rules

## Context Discipline

- Never inspect the entire repository unless explicitly requested.
- Start by identifying the smallest relevant subsystem.
- Read only files directly relevant to the current task.
- Do not recursively inspect unrelated directories.
- Do not dump entire build logs into the conversation.
- Prefer targeted commands and filtered output.
- Avoid re-reading files already inspected unless their contents changed.

## Task Scope

Before modifying code:

1. Identify the task category.
2. Identify the affected subsystem.
3. Identify the minimum required files.
4. Do not expand scope without a concrete reason.

## Build Output

Never use unrestricted build output when diagnosing failures.

Prefer:

    cmake --build <build-dir> 2>&1 | tail -n 100

For compiler diagnostics prefer:

    cmake --build <build-dir> 2>&1 \
      | grep -E 'error:|fatal error:|warning:' \
      | head -n 100

## Testing

Run only the relevant test target first.

Do not run the complete test suite unless:

- explicitly requested, or
- the change affects multiple subsystems.

## Git

Prefer targeted diffs:

    git diff -- <relevant-path>

Never dump the complete repository diff unless explicitly requested.

## C++

- Use modern C++23 or newer.
- Use C++ modules.
- Do not introduce legacy header/source architecture.
- Keep declarations and implementations separated using modules.
- Use Doxygen documentation where appropriate.
- Comments must be English.