# Contributing

Thanks for contributing to OpenProof.

## Before opening a pull request

1. Keep the change focused and avoid unrelated formatting churn.
2. Do not commit credentials, private keys, tokens, database URLs or generated
   local runtime files.
3. Build with the supported GCC 16 toolchain.
4. Run the tests that cover the changed surface.
5. Update the OpenAPI contract or documentation when a public interface changes.

Typical verification:

```bash
cmake --preset gcc-debug
cmake --build --preset gcc-debug
ctest --preset gcc-debug
node sdk/javascript/test.mjs
python3 scripts/verify-openapi.py
```

PostgreSQL integration tests require an explicitly configured disposable test
database. Never point destructive test fixtures at production, staging or a
shared development database.

## Security changes

For security fixes, avoid publishing exploit details before a coordinated fix is
ready. Follow [SECURITY.md](SECURITY.md) for private reporting.
