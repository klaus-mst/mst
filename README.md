# Iterative Drift in DeFi Protocols

Research prototype for MST-IR static analysis.

## Contents

| File | Description |
|---|---|
| `mst-ir-defi-iterative-drift-v0.7.pdf` | Paper |
| `artifacts/mst_ir_analyzer_ast_v0_4.py` | AST-based static analyzer (Python 3.9+, solc required) |
| `artifacts/mst_ir_benchmark.py` | 14-case benchmark suite |
| `artifacts/independent_validation.md` | Independent validation results |

## Usage

```
solc --standard-json input.json | python3 mst_ir_analyzer_ast_v0_4.py
python3 mst_ir_benchmark.py
```
