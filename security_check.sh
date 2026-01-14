#!/bin/bash

echo "--- Running Flake8 (Linting) ---"
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

echo -e "\n--- Running Bandit (Security Scan) ---"
bandit -r . -x ./venv,./labs
