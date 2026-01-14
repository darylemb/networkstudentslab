#!/bin/bash

# Determinar ejecutable de flake8 y bandit
FLAKE8="./venv/bin/flake8"
BANDIT="./venv/bin/bandit"

if [ ! -f "$FLAKE8" ]; then FLAKE8="flake8"; fi
if [ ! -f "$BANDIT" ]; then BANDIT="bandit"; fi

echo "--- Running $FLAKE8 (Linting) ---"
$FLAKE8 . --count --select=E9,F63,F7,F82 --show-source --statistics
$FLAKE8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

echo -e "\n--- Running $BANDIT (Security Scan) ---"
$BANDIT -r . -x ./venv,./labs
