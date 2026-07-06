
For a project like **M2Crypto**, a very effective CI setup is a **matrix build** that tests multiple Python versions and produces wheels. With one VPS runner you can still run these sequentially (or a few in parallel if the machine has enough RAM). See https://www.hetzner.com/cloud/ for prices.

Below is a **practical workflow structure** commonly used for Python libraries.

---

# 1. Recommended runner labels on your VPS

Configure **Gitea Act Runner** with Python container labels:

```yaml
runner:
  labels:
    - python-3.9:docker://python:3.9-bookworm
    - python-3.10:docker://python:3.10-bookworm
    - python-3.11:docker://python:3.11-bookworm
    - python-3.12:docker://python:3.12-bookworm
```

This allows workflows to request different Python versions.

---

# 2. Matrix build workflow

Example `.gitea/workflows/main.yml`

```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  test:
    strategy:
      matrix:
        python:
          - python-3.9
          - python-3.10
          - python-3.11
          - python-3.12

    runs-on: ${{ matrix.python }}

    steps:
      - uses: actions/checkout@v4

      - name: Install system deps
        run: |
          apt update
          apt install -y swig libssl-dev build-essential

      - name: Install Python dependencies
        run: |
          pip install -U pip
          pip install -r dev-requirements.txt

      - name: Build package
        run: |
          pip install -e .

      - name: Run mypy
        run: |
          mypy src/M2Crypto

      - name: Run tests
        run: |
          python -m unittest -v tests.alltests.suite
```

This produces **four CI runs** automatically.

---

# 3. Wheel build job

You usually separate **testing** and **wheel building**.

```yaml
build-wheel:
  runs-on: python-3.11

  steps:
    - uses: actions/checkout@v4

    - name: Install build tools
      run: |
        pip install build wheel

    - name: Build wheel
      run: |
        python -m build

    - uses: actions/upload-artifact@v4
      with:
        name: wheels
        path: dist/*
```

This produces:

```
dist/
   M2Crypto-*.whl
   M2Crypto-*.tar.gz
```

---

# 4. Optional: pip cache (huge speedup)

Add before installs:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/pip
    key: pip-${{ runner.os }}-${{ matrix.python }}-${{ hashFiles('dev-requirements.txt') }}
```

This can reduce CI runtime from **5 minutes → ~1 minute**.

---

# 5. Optional: OpenSSL compatibility matrix

Because **OpenSSL** compatibility matters for M2Crypto, you could also test different library versions.

Example matrix:

```yaml
matrix:
  python: [python-3.10, python-3.11, python-3.12]
  openssl:
    - libssl-dev
```

Then install dynamically.

Many crypto libraries do something like this.

---

# 6. Artifact retention for debugging

Add artifacts when tests fail:

```yaml
- name: Upload logs
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: test-logs
    path: build/
```

Very useful for debugging CI failures.

---

# 7. Expected runtime on a €5 VPS

Typical performance:

| job                  | runtime     |
| -------------------- | ----------- |
| test matrix (4 jobs) | 3–8 minutes |
| wheel build          | 1 minute    |

Even a **1-CPU / 2-GB VPS** handles this comfortably.

---

# 8. One trick many small projects use

Instead of installing dependencies via apt every time, define **custom runner images**:

```
python:3.11-m2crypto
```

with:

```
swig
openssl
build-essential
```

preinstalled.

That can make CI **3–4× faster**.

---

✅ If you want, I can also show you a **very neat CI trick specifically useful for your repo**:

Automatically testing **against multiple OpenSSL ABI versions (1.1 vs 3.x)** using Docker images — which catches many crypto-binding bugs early.
