#!/usr/bin/env bash
# =============================================================================
# analyze_clean.sh — проанализировать образец через чистую песочницу.
#
# Каждый запуск:
#   1) пересоздаёт песочницу с нуля (свежая среда на каждый файл),
#   2) дожидается готовности,
#   3) запускает анализ в контейнере агента.
#
# Использование (файл должен лежать внутри volume /app/data, напр. artifacts):
#   bash scripts/analyze_clean.sh <input_path> [--type url|file|html] [--json]
#
# Пример:
#   docker cp dangerous.html threat_agents:/app/data/artifacts/x.html
#   bash scripts/analyze_clean.sh /app/data/artifacts/x.html --type file
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."   # корень проекта

INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Использование: bash scripts/analyze_clean.sh <input> [--type url|file|html] [--json]" >&2; exit 2; }
shift

TYPE="url"
JSON=""
while [ $# -gt 0 ]; do
  case "$1" in
    --type) TYPE="$2"; shift 2 ;;
    --json) JSON="--json"; shift ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

echo "=== [clean] Свежая песочница перед анализом ==="
bash scripts/reset_sandbox.sh

echo "=== [clean] Анализ: $INPUT (type=$TYPE) ==="
docker exec threat_agents python main.py analyze "$INPUT" --type "$TYPE" $JSON
