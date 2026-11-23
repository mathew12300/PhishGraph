# Verification record

Verified on 23 November 2026 with Python 3.11.9, Flask 3.1.0, NumPy 2.2.3, scikit-learn 1.7.2, SciPy 1.16.2 and joblib 1.5.2.

Command: `python -m unittest discover -s tests -v`

Result: 5 tests passed, exit code 0.

- API behavior and history privacy: passed.
- Fuzzy membership coverage and lexical-axis monotonicity: passed.
- Conflicting training labels: rejected as expected.
- Exact-hostname train/test separation and model reload: passed.
- URL validation and representative feature cases: passed.

The synthetic demo training command completed and produced a model plus metrics. The Flask process reported startup at 127.0.0.1:5000 with debug disabled. HTTP behavior was verified through Flask's in-process test client. External loopback requests were blocked by the execution environment's socket permissions and the browser preview timed out; browser layout, JavaScript interactions and download behavior have not been visually verified. Dependency installation in a fresh virtual environment was not tested; verification used the installed versions listed above.

The Windows SQLite connection cleanup issue found during the initial test run was corrected by explicitly closing connections. The final test run passed without that error.

Synthetic dataset metrics are demonstration results, not a measurement of real-world phishing detection performance.
