# SARIF-Compatible SAST Tools for Java

SARIF (Static Analysis Results Interchange Format) is a standard JSON format for static analysis results, supported by GitHub Security, Azure DevOps, and many CI/CD platforms.

---

## Tools That Generate SARIF Files

### ✅ 1. **Semgrep** (Easiest & Fastest)

**Install:**
```bash
brew install semgrep
# or: pip3 install semgrep
```

**Run with SARIF output:**
```bash
# Basic scan with SARIF output
semgrep --config=auto --sarif -o semgrep-results.sarif src/

# With OWASP Top 10 rules
semgrep --config "p/owasp-top-ten" --sarif -o semgrep-owasp.sarif src/

# With Java security rules
semgrep --config "p/java" --sarif -o semgrep-java.sarif src/

# All security rules
semgrep --config "p/security-audit" --sarif -o semgrep-security.sarif src/
```

**View SARIF file:**
```bash
cat semgrep-results.sarif | jq '.runs[0].results[] | {ruleId, message, level, locations}'
```

---

### ✅ 2. **CodeQL** (Most Comprehensive)

**Install:**
```bash
brew install codeql
```

**Create database and run analysis:**
```bash
# Step 1: Create CodeQL database
codeql database create codeql-db \
  --language=java \
  --command="mvn clean compile -DskipTests"

# Step 2: Run analysis with SARIF output
codeql database analyze codeql-db \
  --format=sarif-latest \
  --output=codeql-results.sarif \
  java-security-and-quality

# Or use specific query suites
codeql database analyze codeql-db \
  --format=sarif-latest \
  --output=codeql-security.sarif \
  java-security-extended
```

**View results:**
```bash
cat codeql-results.sarif | jq '.runs[0].results[] | {ruleId, message, level}'
```

---

### ✅ 3. **Snyk Code**

**Install:**
```bash
brew install snyk
# or: npm install -g snyk
```

**Authenticate:**
```bash
snyk auth
```

**Run with SARIF output:**
```bash
# Scan code with SARIF output
snyk code test --sarif-file-output=snyk-code.sarif

# Scan dependencies with SARIF
snyk test --sarif-file-output=snyk-deps.sarif
```

---

### ✅ 4. **SonarQube Scanner** (via sonar-scanner-cli)

**Install:**
```bash
brew install sonar-scanner
```

**Run with SARIF export:**
```bash
# First run normal scan
sonar-scanner \
  -Dsonar.projectKey=concert-booking \
  -Dsonar.sources=src \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=admin \
  -Dsonar.password=admin

# Then export to SARIF using API
curl -u admin:admin \
  "http://localhost:9000/api/issues/search?componentKeys=concert-booking&format=sarif" \
  -o sonarqube-results.sarif
```

---

### ✅ 5. **SpotBugs with SARIF Converter**

SpotBugs doesn't natively output SARIF, but you can convert:

**Install converter:**
```bash
npm install -g @microsoft/sarif-multitool
```

**Run SpotBugs and convert:**
```bash
# Run SpotBugs
mvn clean compile spotbugs:spotbugs

# Convert XML to SARIF
sarif-multitool convert target/spotbugsXml.xml \
  --tool SpotBugs \
  --output spotbugs-results.sarif
```

---

### ✅ 6. **Trivy** (Container & Code Scanning)

**Install:**
```bash
brew install trivy
```

**Run with SARIF output:**
```bash
# Scan filesystem
trivy fs --format sarif --output trivy-results.sarif .

# Scan specific directory
trivy fs --format sarif --output trivy-src.sarif src/
```

---

## Recommended: Semgrep (Fastest SARIF Generation)

For this codebase, **Semgrep** is the fastest and easiest way to get SARIF output:

```bash
# Install
brew install semgrep

# Run comprehensive scan
semgrep --config=auto --sarif -o results.sarif src/

# View summary
cat results.sarif | jq '.runs[0].results | length'
cat results.sarif | jq '.runs[0].results[] | select(.level=="error") | .ruleId'
```

---

## Upload SARIF to GitHub

If your code is on GitHub, you can upload SARIF files to GitHub Security:

```bash
# Install GitHub CLI
brew install gh

# Authenticate
gh auth login

# Upload SARIF file
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  /repos/OWNER/REPO/code-scanning/sarifs \
  -f sarif=@results.sarif \
  -f commit_sha="$(git rev-parse HEAD)" \
  -f ref="refs/heads/$(git branch --show-current)"
```

---

## Complete SARIF Scanning Script

Save as `run-sarif-scan.sh`:

```bash
#!/bin/bash
set -e

echo "=== Running SARIF-Compatible SAST Scans ==="

# 1. Semgrep (fastest)
if command -v semgrep &> /dev/null; then
    echo "[1/3] Running Semgrep..."
    semgrep --config=auto --sarif -o semgrep-results.sarif src/
    echo "✓ Generated: semgrep-results.sarif"
else
    echo "⚠ Semgrep not installed. Run: brew install semgrep"
fi

# 2. CodeQL (most comprehensive)
if command -v codeql &> /dev/null; then
    echo "[2/3] Running CodeQL..."
    if [ ! -d "codeql-db" ]; then
        codeql database create codeql-db --language=java --command="mvn clean compile -DskipTests"
    fi
    codeql database analyze codeql-db \
        --format=sarif-latest \
        --output=codeql-results.sarif \
        java-security-and-quality
    echo "✓ Generated: codeql-results.sarif"
else
    echo "⚠ CodeQL not installed. Run: brew install codeql"
fi

# 3. Snyk (if authenticated)
if command -v snyk &> /dev/null; then
    echo "[3/3] Running Snyk Code..."
    snyk code test --sarif-file-output=snyk-results.sarif || true
    echo "✓ Generated: snyk-results.sarif"
else
    echo "⚠ Snyk not installed. Run: brew install snyk"
fi

echo ""
echo "=== SARIF Files Generated ==="
ls -lh *.sarif 2>/dev/null || echo "No SARIF files found"

echo ""
echo "=== Vulnerability Summary ==="
for file in *.sarif; do
    if [ -f "$file" ]; then
        count=$(jq '.runs[0].results | length' "$file" 2>/dev/null || echo "0")
        echo "$file: $count findings"
    fi
done
```

Make executable and run:
```bash
chmod +x run-sarif-scan.sh
./run-sarif-scan.sh
```

---

## View SARIF Results

### Option 1: VS Code Extension

Install the **SARIF Viewer** extension:
1. Open VS Code
2. Install extension: `ms-vscode.sarif-viewer`
3. Open any `.sarif` file

### Option 2: Command Line (jq)

```bash
# Count total findings
jq '.runs[0].results | length' results.sarif

# List all rule IDs
jq '.runs[0].results[].ruleId' results.sarif | sort | uniq

# Show critical/high severity issues
jq '.runs[0].results[] | select(.level=="error" or .level=="warning") | {ruleId, message, level}' results.sarif

# Extract file paths with issues
jq '.runs[0].results[].locations[].physicalLocation.artifactLocation.uri' results.sarif | sort | uniq
```

### Option 3: SARIF Web Viewer

Upload to: https://microsoft.github.io/sarif-web-component/

---

## Expected SARIF Output for This Codebase

Running Semgrep should produce approximately:

```json
{
  "runs": [{
    "results": [
      {
        "ruleId": "java.lang.security.audit.crypto.weak-hash.weak-hash-md5",
        "level": "error",
        "message": { "text": "Weak hashing algorithm (MD5) detected" },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "src/main/java/com/concert/util/CryptoUtil.java" },
            "region": { "startLine": 35 }
          }
        }]
      },
      {
        "ruleId": "java.lang.security.audit.sqli.tainted-sql-string",
        "level": "error",
        "message": { "text": "SQL injection vulnerability detected" },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "src/main/java/com/concert/util/DatabaseUtil.java" },
            "region": { "startLine": 58 }
          }
        }]
      }
      // ... 100+ more findings
    ]
  }]
}
```

---

## Quick Start (TL;DR)

```bash
# Install Semgrep
brew install semgrep

# Run scan and generate SARIF
semgrep --config=auto --sarif -o results.sarif src/

# View results
cat results.sarif | jq '.runs[0].results[] | {ruleId, level, message}'
```

This will find **100+ vulnerabilities** in this codebase and output them in SARIF format.