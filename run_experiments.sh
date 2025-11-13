#!/bin/bash

# Epoch durations in milliseconds
EPOCH_DURATIONS=(200 400 500 600 800 1000 2000 4000 5000)
OUTPUT_FILE="results.txt"

# Clear previous results
> "$OUTPUT_FILE"

echo "Sketch Performance Evaluation Results" >> "$OUTPUT_FILE"
echo "======================================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Build the program first
echo "Building the program..."
if ! TERM=xterm ./build.sh; then
    echo "Build failed!"
    exit 1
fi

echo "Build successful!"
echo "" >> "$OUTPUT_FILE"
echo "Running evaluations with different epoch durations..." >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Run for each epoch duration
for duration in "${EPOCH_DURATIONS[@]}"
do
    echo "Running with EPOCH_DURATION = ${duration}ms..."

    # Run the program and capture output
    if ./build/main "$duration" 2>&1 | tee temp_output.txt; then
        # Extract the summary metrics section
        echo "EPOCH_DURATION: ${duration}ms" >> "$OUTPUT_FILE"
        echo "------------------------" >> "$OUTPUT_FILE"

        # Extract the average metrics table including the data rows
        awk '/Average Metrics Across All Epochs/,/============================================================/ { if ($0 !~ /^$/) print }' temp_output.txt | tail -n +2 | head -n -1 >> "$OUTPUT_FILE"

        echo "" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"

        echo "Completed ${duration}ms - results saved to $OUTPUT_FILE"
    else
        echo "Error running with duration ${duration}ms" >> "$OUTPUT_FILE"
        echo "Error running with duration ${duration}ms"
    fi

    # Clean up temp file
    rm -f temp_output.txt

    # Small delay between runs
    sleep 1
done

echo "All evaluations completed!"
echo "Results saved to: $OUTPUT_FILE"