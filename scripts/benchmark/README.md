# Ares Benchmark

Measures finding quality against a known-vulnerable corpus.

## Structure

```
benchmark/
  corpus/          # Vulnerable targets (docker-compose environments)
  ground_truth/    # Expected findings per target (JSON)
  run.py           # Driver: runs Ares scans, compares to ground truth
  judge.py         # LLM judge: scores findings vs ground truth
  results/         # Output (auto-created)
```

## Usage

```bash
# Start a corpus environment
docker compose -f corpus/api-broken-auth/docker-compose.yml up -d

# Run the benchmark
python3 scripts/benchmark/run.py --target http://localhost:3000 --ground-truth corpus/api-broken-auth/ground_truth.json

# Results summary
cat scripts/benchmark/results/latest.json
```

## Scoring

The LLM judge scores each finding on:
- **Validity** (0–10): is this a real vulnerability or a false positive?
- **Precision** (0–10): is the finding description accurate?
- **Coverage** (0–10): does it match the expected ground truth?

Overall score = mean across all three dimensions.
