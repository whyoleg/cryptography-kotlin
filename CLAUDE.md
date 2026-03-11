# CLAUDE.md

Agent-specific guidance for working with this repository. For full project documentation, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Quick Reference

- **Build all**: `just build`
- **Build module**: `just build core` or `just build provider-jdk`
- **Test JDK**: `just test-provider-jdk`
- **Test with filter**: `just test-provider-jdk "*AesGcm*"`
- **All commands**: `just --list` or see [CONTRIBUTING.md](CONTRIBUTING.md)

## Decision-Making Priorities

When implementing features, prioritize in this order:

1. **API consistency** - Follow existing patterns exactly
2. **Completeness** - Implement for all applicable providers
3. **Performance** - Optimize where it matters
4. **Simplicity** - Keep code simple, but not at the cost of above

## Workflow for Changes

1. **Explore** - Understand existing code, look at similar algorithms/APIs
2. **Plan** - Design the approach before implementing
3. **Implement** - Follow existing patterns
4. **Test** - All test types required for new algorithms (default, compatibility, testvectors)
5. **Document** - Update `docs/` if user-facing
6. **Do not commit** - Leave commits to the user

## Keeping Documentation Updated

When you discover new information during a session, proactively update the relevant documentation:

| Discovery                         | Update            |
|-----------------------------------|-------------------|
| New pattern or convention         | `CLAUDE.md`       |
| Build/test command or workflow    | `CONTRIBUTING.md` |
| User-facing feature or API        | `docs/`           |
| Provider limitation or capability | `docs/providers/` |

Ask before making documentation changes if unsure whether the information is project-specific or session-specific.

## Links

- [CONTRIBUTING.md](CONTRIBUTING.md) - Full reference: project overview, architecture, build commands, test commands, development workflow
- [docs/](docs/) - Library documentation
- [docs/providers/](docs/providers/) - Provider-specific documentation and support matrices
