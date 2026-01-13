# ANANKE (Ἀνάγκη)

> *"Inevitability finds every vulnerability"*

**IDOR Hunter + Race Condition Scanner**

## Installation

```bash
cd HikariSystem\ Ananke
go mod tidy
go build -o ananke.exe ./cmd/ananke
```

## Usage

### IDOR Scanning
```bash
# Basic IDOR scan
./ananke idor "https://api.target.com/users/{id}" --range 1-1000

# With authentication
./ananke idor "https://api.target.com/orders/{id}" -H "Bearer TOKEN" --range 1-100 -t 20
```

### Race Condition Testing
```bash
# Coupon abuse test
./ananke race "https://api.target.com/redeem" -X POST -d '{"coupon":"DISCOUNT50"}' -H "Bearer TOKEN" --threads 100

# Double spending test  
./ananke race "https://api.target.com/transfer" -X POST -d '{"amount":100}' --threads 50
```

## Features

- [x] High-performance HTTP client (fasthttp)
- [x] IDOR ID fuzzing (numeric ranges)
- [x] Response diffing
- [x] Race condition with goroutine synchronization
- [x] Precise timing control
- [ ] UUID manipulation
- [ ] JSON output
- [ ] HTML reports

## HikariSystem Security Tools

---

> ⚠️ **MVP Release** - This is a test/proof-of-concept version. Work in progress.

### Credits
- **Created by:** [@LXrdKnowkill](https://github.com/LXrdKnowkill)
- **Reviewed by:** [@ThreatBiih](https://github.com/ThreatBiih)
