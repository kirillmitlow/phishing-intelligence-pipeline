#!/usr/bin/env bash
# =============================================================================
# reset_sandbox.sh — пересоздаёт песочницу (sandbox_service) с нуля.
#
# Назначение: изолированный анализ образцов в чистой среде.
# Любые остатки в рантайме контейнера (процессы, мусор в /tmp, состояние
# headless-Chromium) удаляются вместе со старым контейнером. Артефакты и БД
# в volume data_volume сохраняются (база знаний и отчеты).
#
# ВАЖНО: рестарт делается СНАРУЖИ (с хоста), а не из контейнера агента,
# чтобы НЕ давать агенту docker-socket (это разорвало бы изоляцию).
#
# Использование:
#   bash scripts/reset_sandbox.sh            # пересоздать + ждать готовности
#   FORCE=1 bash scripts/reset_sandbox.sh    # принудительно (даже если не был запущен)
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."   # корень проекта
COMPOSE="docker compose"
SVC="sandbox_service"      # имя сервиса в compose (для: docker compose up <svc>)
CT="threat_sandbox"        # ИМЯ КОНТЕЙНЕРА (container_name) — для docker exec/inspect

echo "[reset] Пересоздаю песочницу $SVC ..."
# --force-recreate создаёт НОВЫЙ контейнер (свежий overlay + /tmp), volume сохраняется
$COMPOSE up -d --force-recreate "$SVC"

# Ждём готовности через внутренний /ping (максимум ~20 попыток по 1с)
echo "[reset] Жду готовности /ping ..."
for i in $(seq 1 20); do
  if docker exec "$CT" python -c "import urllib.request,sys; \
     urllib.request.urlopen('http://127.0.0.1:8400/ping', timeout=1)" 2>/dev/null; then
    echo "[reset] OK — песочница готова (статус: $(docker inspect -f '{{.State.Status}}' $CT))"
    exit 0
  fi
  sleep 1
done

echo "[reset] ОШИБКА: песочница не поднялась за 20с" >&2
exit 1
