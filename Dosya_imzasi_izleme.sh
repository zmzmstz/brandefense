"""
[Bash] Günlük Hayat Senaryosu 2 – Dosya İmzası İzleme (Cron Uyumlu)
Senaryo:
Sunucunuzda /opt/scripts/ klasöründe çalışan bazı kritik script dosyaları var. Bunların değiştirilip değiştirilmediğini her gece kontrol etmek istiyorsunuz.
Görev:
Bash script aşağıdaki işlevleri yerine getirmelidir:
•	sha256sum ile mevcut dosyaların hash değerlerini baseline_hashes.txt içine yaz (ilk çalışmada)
•	Sonraki çalışmalarda:
o	Aynı klasörü tekrar kontrol et
o	Değişmiş, silinmiş veya yeni eklenmiş dosyaları tespit et
o	Tüm farkları integrity_report.txt dosyasına yaz
•	Cron uyumlu olması için terminal çıktısı olmamalı, sadece dosya üretmeli
"""

#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

TARGET_DIR="/opt/scripts"
BASELINE_FILE="${SCRIPT_DIR}/baseline_hashes.txt"
REPORT_FILE="${SCRIPT_DIR}/integrity_report.txt"
CURRENT_HASHES_FILE=$(mktemp)

trap 'rm -f "$CURRENT_HASHES_FILE"' EXIT

generate_hashes() {
    local dir_to_scan="$1"
    local output_file="$2"

    if [ ! -d "$dir_to_scan" ]; then
        >"$output_file"
        return
    fi

    (
        cd "$dir_to_scan" || exit 1
        
        local files_found=0
        for item in *; do 
            if [ -f "$item" ]; then 
                sha256sum "$item" 
                files_found=1
            fi
        done
        if [ "$files_found" -eq 0 ]; then
            echo -n ""
        fi
    ) | sort > "$output_file" 
}

if [ ! -d "$TARGET_DIR" ]; then
    echo "Integrity Check Report - $(date)" > "$REPORT_FILE"
    echo "------------------------------------" >> "$REPORT_FILE"
    echo "ERROR: Monitored directory $TARGET_DIR does not exist." >> "$REPORT_FILE"
    exit 1
fi

if [ ! -f "$BASELINE_FILE" ]; then
    generate_hashes "$TARGET_DIR" "$BASELINE_FILE"
    echo "Integrity Check Report - $(date)" > "$REPORT_FILE"
    echo "------------------------------------" >> "$REPORT_FILE"
    echo "Target Directory: $TARGET_DIR" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "Baseline created: $BASELINE_FILE" >> "$REPORT_FILE"
    echo "No comparison done on first run." >> "$REPORT_FILE"
    exit 0
fi

generate_hashes "$TARGET_DIR" "$CURRENT_HASHES_FILE"

echo "Integrity Check Report - $(date)" > "$REPORT_FILE"
echo "------------------------------------" >> "$REPORT_FILE"
echo "Target Directory: $TARGET_DIR" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

declare -A baseline_map
declare -A current_map_for_deletion_check

any_changes=0

while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -z "$line" ]]; then continue; fi
    hash_val="${line%% *}"
    file_name="${line#*  }"
    baseline_map["$file_name"]="$hash_val"
done < "$BASELINE_FILE"

while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -z "$line" ]]; then continue; fi
    current_hash_val="${line%% *}"
    current_file_name="${line#*  }"
    
    current_map_for_deletion_check["$current_file_name"]=1

    if [[ -z "${baseline_map[$current_file_name]+_}" ]]; then
        echo "NEW: $current_file_name" >> "$REPORT_FILE"
        any_changes=1
    elif [[ "${baseline_map[$current_file_name]}" != "$current_hash_val" ]]; then
        echo "MODIFIED: $current_file_name" >> "$REPORT_FILE"
        any_changes=1
    fi
done < "$CURRENT_HASHES_FILE"

for file_name in "${!baseline_map[@]}"; do
    if [[ -z "${current_map_for_deletion_check[$file_name]+_}" ]]; then
        echo "DELETED: $file_name" >> "$REPORT_FILE"
        any_changes=1
    fi
done

if [ "$any_changes" -eq 0 ]; then
    echo "No changes detected in $TARGET_DIR." >> "$REPORT_FILE"
fi

echo "" >> "$REPORT_FILE"
echo "Integrity check complete." >> "$REPORT_FILE"

exit 0