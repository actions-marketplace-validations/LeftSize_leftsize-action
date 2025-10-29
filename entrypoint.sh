#!/bin/bash
set -e

echo "::group::LeftSize Cloud Cost Optimization Scanner"
echo "Starting LeftSize scan..."
echo "Cloud Provider: ${LEFTSIZE_CLOUD_PROVIDER}"
echo "Verbose: ${LEFTSIZE_VERBOSE}"
echo "::endgroup::"

# Run the Python scanner
python3 /action/run.py

# Capture exit code
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ LeftSize scan completed successfully"
else
    echo "❌ LeftSize scan failed with exit code $EXIT_CODE"
fi

exit $EXIT_CODE
