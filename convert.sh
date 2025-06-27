#!/bin/bash

# Fixed Traefik JSON to GoAccess-compatible log converter using proven jq logic
INPUT_DIR=${1:-"."}
OUTPUT_DIR=${2:-"converted"}
MERGED_FILE="all_access.log"

echo "🚀 Traefik Log Converter (with verified jq logic)"
echo "Input directory: $INPUT_DIR"
echo "Output directory: $OUTPUT_DIR"
echo "=================================="

mkdir -p "$OUTPUT_DIR"

TOTAL_FILES=$(find "$INPUT_DIR" -name "*.log" -type f | wc -l)
echo "Found $TOTAL_FILES log files"

COUNTER=0
TOTAL_ENTRIES=0

convert_file() {
    local input_file="$1"
    local output_file="$2"

    echo "Converting: $(basename "$input_file")"

    if [ ! -s "$input_file" ]; then
        echo "  ⚠️  File is empty, skipping..."
        return 0
    fi

    local file_entries=0

    while IFS= read -r line; do
        if [[ -z "$line" || ! "$line" =~ ^\{.*\}$ ]]; then
            continue
        fi

        # Fixed jq command with correct sub() pattern
        converted_line=$(echo "$line" | jq -r '
          if .ClientAddr and .StartUTC and .RequestMethod and .RequestPath and .RequestProtocol and .DownstreamStatus then
            ((.StartUTC | sub("\\.\\d+Z$"; "Z") | strptime("%Y-%m-%dT%H:%M:%SZ")) |
            strftime("[%d/%b/%Y:%H:%M:%S +0000]")) as $timestamp |
            (.Duration // 0 / 1000000 | floor) as $response_time |
            (.ClientAddr | split(":")[0]) as $client_ip |
            (.RequestPath // "/") as $path |
            ($client_ip + " - - " + $timestamp + " \"" + .RequestMethod + " " + $path + " " + .RequestProtocol + "\" " +
             (.DownstreamStatus|tostring) + " " + ((.DownstreamContentSize // 0)|tostring) + " " +
             ($response_time|tostring) + " \"" + (.RequestHost // "-") + "\"")
          else
            empty
          end
        ' 2>/dev/null)

        if [[ -n "$converted_line" && "$converted_line" != "null" ]]; then
            echo "$converted_line" >> "$output_file"
            ((file_entries++))
        fi

    done < "$input_file"

    echo "  ✅ Converted $file_entries entries"
    return $file_entries
}

echo "" > "$OUTPUT_DIR/$MERGED_FILE"

for log_file in "$INPUT_DIR"/*.log; do
    if [ -f "$log_file" ]; then
        COUNTER=$((COUNTER + 1))
        echo "[$COUNTER/$TOTAL_FILES] Processing: $(basename "$log_file")"

        convert_file "$log_file" "$OUTPUT_DIR/$MERGED_FILE"
        entries_added=$?
        TOTAL_ENTRIES=$((TOTAL_ENTRIES + entries_added))

        PERCENT=$((COUNTER * 100 / TOTAL_FILES))
        echo "  Progress: $PERCENT% | Total entries: $TOTAL_ENTRIES"
        echo ""
    fi
done

if [ -s "$OUTPUT_DIR/$MERGED_FILE" ]; then
    echo "✅ Conversion completed successfully!"
    echo "Total processed files: $COUNTER"
    echo "Output file: $OUTPUT_DIR/$MERGED_FILE"
    echo "File size: $(du -h "$OUTPUT_DIR/$MERGED_FILE" | cut -f1)"
    echo "Total log entries: $(wc -l < "$OUTPUT_DIR/$MERGED_FILE")"

    echo ""
    echo "📋 Sample converted entries:"
    echo "----------------------------"
    head -3 "$OUTPUT_DIR/$MERGED_FILE"
    echo "----------------------------"
else
    echo "❌ No entries were converted!"
    echo "Please check:"
    echo "1. Log files contain valid JSON"
    echo "2. JSON structure matches expected format"
    echo "3. jq is installed and working"
    exit 1
fi
