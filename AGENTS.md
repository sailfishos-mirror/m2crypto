The role of this file is to describe common mistakes and confusion
points that agents might encounter as they work in this project. If you
ever encounter something in the project that surprises you, please,
alert the developer working with you and indicate that this is the case
in the AgentMD file to help prevent future agents from having the same
issue.

# Building M2Crypto

## Dependencies

*   Python 3 (>= 3.6)
*   SWIG
*   OpenSSL (development libraries)
*   A C compiler (like GCC)

## SWIG Integration

M2Crypto uses SWIG to generate Python bindings from OpenSSL C headers.
SWIG options are configured in the `finalize_options()` method of
`_M2CryptoBuildExt` in `setup.py`.

# Development Conventions

## Coding Style

*   **Type Checking**: Run `make mypy`.

## Documentation

*   Use docstrings for modules, classes, and functions.
*   Update `doc/` when making significant changes.

# Testing M2Crypto

Tests are located in `tests/` and use Python's `unittest`. Don't use
`pytest`.

## Running Tests

*   `make check`: **Primary command.** Runs all unit tests using `unittest discover`.
*   `make doctest`: Runs doctests on documentation.

### Running Individual Tests

To run a single test file or method, you must set `PYTHONPATH` to the local build directory.

```bash
# Set up the environment (or look up BUILD_LIB_DIR from make output)
export PYTHONPATH="$(find build -maxdepth 1 -type d -name "lib.*" | head -n 1)"
```

## Test Certificates

Information on creating test certificates is available in `tests/README`.
