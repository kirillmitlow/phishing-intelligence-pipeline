import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import List, Optional

from agents.base_agent import BaseAgent
from core import storage
from core.pipeline import (
    collect_url,
    collect_html,
    collect_file,
    analyze_brand,
    generate_signatures,
    analyze_advanced_indicators,
    _extract_domains,
    _hash_file,
    read_sample_html,
    ARTIFACTS_DIR,
)
from core import campaign_cluster

COLLECTOR_MAX_STEPS = int(os.getenv("COLLECTOR_MAX_STEPS", "10"))
ANALYST_MAX_STEPS = int(os.getenv("ANALYST_MAX_STEPS", "10"))
URL_RE = re.compile(r"https?://[^\s\"'<>\\`)},\]]+")


def _kind_by_suffix(path: Path) -> str:
    suf = path.suffix.lower()
    return {
        ".png": "screenshot", ".jpg": "image", ".jpeg": "image",
        ".html": "html", ".pdf": "attachment", ".zip": "attachment",
        ".md": "document", ".txt": "document", ".eml": "attachment",
    }.get(suf, "file")


def save_trace(conn, sample_id: int, agent_name: str, trace: List[dict]) -> None:
    for rec in trace:
        content = rec.get("content", "")
        if rec.get("thought"):
            content = f"{rec['thought']}\n{content}"
        storage.add_trace(
            conn, sample_id, agent_name,
            step=int(rec.get("step", 0)),
            kind=rec.get("kind", "action"),
            content=str(content)[:8000],
            args=rec.get("args"),
        )


def _harvest_urls_from_trace(trace: List[dict]) -> List[str]:
    found = []
    for rec in trace:
        text = str(rec.get("content", ""))
        args = rec.get("args")
        if args:
            text += " " + json.dumps(args, ensure_ascii=False)
        found.extend(URL_RE.findall(text))
    seen, out = set(), []
    for u in found:
        u = u.rstrip(".,;:\\`")
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def ensure_input_on_volume(input_ref: str, task_id: str) -> str:
    p = Path(input_ref)
    if not p.is_absolute() or not p.exists():
        return input_ref
    try:
        if str(p.resolve()).startswith(str(ARTIFACTS_DIR.resolve())):
            return str(p)
    except Exception:
        pass
    dest_dir = ARTIFACTS_DIR / task_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(dest_dir, 0o777)
    except Exception:
        pass
    dest = dest_dir / f"input_{p.name}"
    try:
        shutil.copy2(p, dest)
        try:
            os.chmod(dest, 0o666)
        except Exception:
            pass
        return str(dest)
    except Exception:
        return input_ref


def finalize_collected(conn, sample_id: int, task_id: str) -> dict:
    task_dir = ARTIFACTS_DIR / task_id
    added, skipped = [], 0
    existing_paths = {a["path"] for a in storage.list_artifacts(conn, sample_id)}

    if task_dir.exists():
        for f in sorted(task_dir.rglob("*")):
            if not f.is_file():
                continue
            path_str = str(f)
            if path_str in existing_paths:
                skipped += 1
                continue
            try:
                md5, sha = _hash_file(f)
            except Exception:
                continue
            storage.add_artifact(conn, sample_id, _kind_by_suffix(f), path_str,
                                 md5, sha, {"size": f.stat().st_size,
                                            "source": "collector_run"})
            added.append(path_str)
    return {"added": added, "skipped_existing": skipped}


# ---------------------------------------------------------------- agent tasks
def _collector_task(input_type: str, input_ref: str, task_id: str, seed: dict) -> str:
    seed_desc = json.dumps(seed, ensure_ascii=False, default=str)[:4000]
    return f"""Стартовая точка ({input_type}): {input_ref[:300]}

Подпапка артефактов этого образца: **{task_id}** — во ВСЕ вызовы инструментов
передавай именно её как task_id, чтобы всё собиралось в одну папку.

Что уже собрано детерминированной подготовкой (стартовый шаг):
{seed_desc}

Твоя работа — продолжить сбор ВГЛУБЬ:
1. Просмотри найденные ссылки. Самые подозрительные (редиректоры, короткие
   ссылки, пути вида /login /verify /update, файлы .pdf/.zip/.html/.docx,
   form action) — исследуй дальше: страницы рендери через render_page,
   файлы скачивай через download_file.
2. Скачанные файлы разбери: архивы → unpack_attachment, документы →
   extract_document, PDF → render_pdf_to_png, картинки → extract_qr.
3. Если в коде страниц есть обфускация (atob/eval/document.write) — вырежи
   подозрительный фрагмент и прогони через eval_js, чтобы достать спрятанные ссылки.
4. Найденные новые ссылки/файлы обрабатывай так же. Глубина — до 3 уровней,
   всего не больше ~20 вызовов инструментов: выбирай самое подозрительное.

Ограничения:
- НЕ выноси вердикт о фишинге — только собирай.
- Всё, что скачиваешь/рендеришь, сохраняется само — дополнительно ничего никуда не пиши.
- Если инструмент вернул ошибку вида «не резолвится / не отвечает / таймаут /
  render error» — адрес недоступен. Зафиксируй это и НЕ повторяй вызов для того
  же адреса (один адрес = максимум одна попытка).
- В run_shell строго запрещены связки команд (&&, ||, |, ;, >, <, $) и curl. Запускай строго по одной атомарной команде (grep, head, tail, file, wc, ls, strings). Для сети используй только download_file и render_page.
- Ссылки на домены-заглушки вида *.example, *.test, localhost обычно не живут —
  их достаточно просто перечислить в итогах без попыток открыть.

Когда закончишь — выдай итог СТРУКТУРИРОВАННО:
## Итог сбора
- Обработанные ссылки: (список с пометкой куда ведут)
- Скачанные файлы: (пути)
- Найденные в них ссылки/QR/документы
- Что осталось необработанным и почему
"""


def _analyst_task(sample_id: int, artifacts: List[dict], urls: List[dict],
                  findings: List[dict], collector_note: str) -> str:
    art_desc = [{"path": a["path"], "kind": a["kind"], "sha256": a.get("sha256"),
                 "md5": a.get("md5")} for a in artifacts][:60]
    url_desc = [{"url": u["url"], "kind": u.get("kind"), "final": u.get("final_url")}
                for u in urls][:60]
    find_desc = [{"technique": f["technique"], "severity": f.get("severity")}
                 for f in findings]
    return f"""Сборщик уже отработал по образцу #{sample_id}. Вот что собрано.

Артефакты (лежат на общем томе /app/data):
{json.dumps(art_desc, ensure_ascii=False)}

Найденные ссылки и редиректы:
{json.dumps(url_desc, ensure_ascii=False)}

Уже зафиксированные признаки (детерминированные):
{json.dumps(find_desc, ensure_ascii=False)}

Заметки сборщика:
{collector_note[:4000]}

Твоя работа — извлечь структурированный профиль признаков угроз (Threat Intelligence Profile) для антиспам-движка:
1. Посмотри скриншоты через analyze_screenshot — какой бренд имитируется,
   есть ли форма логина (credential form), несоответствие домена.
2. Подозрительные фрагменты кода (из результатов сборщика) разбери через
   analyze_snippet — выяви обфускацию, скрытую отправку данных.
3. Если данных не хватает — собери недостающее сам (все инструменты доступны).
4. Хэши артефактов уже посчитаны и приведены выше — переиспользуй их,
   пересчитывать через hash_artifacts нужно только для новых файлов.
5. Не делай бинарный вывод «скам/не скам» — образец уже в базе подозрительных,
   твоя цель — зафиксировать техники, бренд, артефакты и reason codes.

Финальный ответ выдай СТРОГО в таком формате:
## Threat Intelligence Profile
- Имитируемый бренд: <название или «не определён»>
- Принадлежность к целевому списку (in_target): да / нет
- Доменное несоответствие: да / нет (пояснение)
- Техники: <список: credential_form / brand_impersonation / qr_phish / obfuscated_js / hidden_iframe / redirect_abuse / html_attachment / другое>
- Хэши ключевых артефактов: <sha256 из списка выше, которые относятся к делу>
- Reason codes: <структурированные машиночитаемые коды признаков для правил антиспама, например: BRAND_IMPERSONATION_TARGET, CREDENTIAL_HARVESTING_FORM>
- Уверенность: 0.0–1.0
"""


def run_agent_pipeline(input_type: str, input_ref: str, db_path: Optional[str] = None) -> dict:
    storage.init_db(db_path)
    conn = storage.get_conn(db_path)
    try:
        sample_id = storage.create_sample(conn, input_type, input_ref[:200])
        conn.commit()
        storage.set_sample_status(conn, sample_id, "collecting")
        conn.commit()

        task_id = f"sample_{sample_id}"
        task_dir = ARTIFACTS_DIR / task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(ARTIFACTS_DIR, 0o777)
            os.chmod(task_dir, 0o777)
        except Exception:
            pass

        # Вход-файл должен лежать на общем томе — иначе песочница его не увидит.
        if input_type == "file":
            input_ref = ensure_input_on_volume(input_ref, task_id)

        # ---------- 1. детерминированная подготовка стартовой точки
        if input_type == "url":
            seed = collect_url(conn, sample_id, input_ref, task_id)
        elif input_type == "html":
            seed = collect_html(conn, sample_id, input_ref, task_id)
        elif input_type == "file":
            seed = collect_file(conn, sample_id, input_ref, task_id)
        else:
            storage.set_sample_status(conn, sample_id, "failed")
            conn.commit()
            return {"ok": False, "error": f"неизвестный тип входа: {input_type}"}

        if seed.get("ok") is False:
            storage.set_sample_status(conn, sample_id, "failed")
            conn.commit()
            return {"ok": False, "sample_id": sample_id,
                    "error": seed.get("error")}
        conn.commit()

        # ---------- 2. Агент-Сборщик (свободный ReAct в рамках задачи сбора)
        try:
            collector = BaseAgent.from_config("collector_agent")
            collector_result = collector.run(
                _collector_task(input_type, input_ref, task_id, seed),
                max_steps=COLLECTOR_MAX_STEPS,
            )
        except Exception as e:
            collector_result = {"result": f"Collector error: {e}", "trace": [{"step": 0, "kind": "error", "content": str(e)}]}
        save_trace(conn, sample_id, "collector_agent", collector_result.get("trace", []))
        conn.commit()

        # ---------- 3. детерминированная фиксация собранного
        fin = finalize_collected(conn, sample_id, task_id)
        # ссылки, которые агент видел в ходе работы, — в таблицу urls
        existing = {u["url"] for u in storage.list_urls(conn, sample_id)}
        for u in _harvest_urls_from_trace(collector_result.get("trace", [])):
            if u not in existing:
                storage.add_url(conn, sample_id, u, kind="collector_found")
                existing.add(u)
        conn.commit()

        # ---------- 4. Агент-Аналитик (свободный ReAct в рамках задачи анализа)
        artifacts = storage.list_artifacts(conn, sample_id)
        urls = storage.list_urls(conn, sample_id)
        findings = storage.list_findings(conn, sample_id)

        try:
            analyst = BaseAgent.from_config("analyst_agent")
            analyst_result = analyst.run(
                _analyst_task(sample_id, artifacts, urls, findings,
                              collector_result.get("result", "")),
                max_steps=ANALYST_MAX_STEPS,
            )
        except Exception as e:
            analyst_result = {"result": f"Analyst error: {e}", "trace": [{"step": 0, "kind": "error", "content": str(e)}]}
        save_trace(conn, sample_id, "analyst_agent", analyst_result.get("trace", []))
        conn.commit()

        # ---------- 5. финализация: бренд (VLM) + DOM + сигнатуры + кампании
        artifacts = storage.list_artifacts(conn, sample_id)
        urls = storage.list_urls(conn, sample_id)
        screenshots = [a["path"] for a in artifacts if a["kind"] == "screenshot"]
        domains = _extract_domains([u.get("url", "") for u in urls])
        analyze_brand(conn, sample_id, screenshots[:3], domains)

        # Глубокий анализ HTML/DOM
        task_id = f"sample_{sample_id}"
        html_content = read_sample_html(task_id, input_type, input_ref)
        adv_results = {}
        if html_content:
            final_u = (urls[0].get("final_url") or urls[0].get("url") or "") if urls else ""
            adv_results = analyze_advanced_indicators(conn, sample_id, html_content, final_u)

        generate_signatures(conn, sample_id, urls, artifacts)

        # Кластеризация кампаний (Task.md: Campaign Tracking)
        brands = storage.list_brands(conn, sample_id)
        primary_brand = brands[0]["brand"] if brands else None
        dom_hash_val = adv_results.get("dom_hash")
        campaign_cluster.cluster_sample_into_campaign(
            conn, sample_id, target_brand=primary_brand, dom_hash=dom_hash_val
        )

        # Сохранение итогового Threat Intelligence отчета в markdown-артефакт
        verdict = analyst_result.get("result", "")
        if not verdict or "лимит шагов" in verdict or "Collector error" in verdict or "Analyst error" in verdict:
            sample_brands = storage.list_brands(conn, sample_id)
            sample_findings = storage.list_findings(conn, sample_id)
            sample_sigs = storage.list_signatures(conn, sample_id)
            sample_obj = storage.get_sample(conn, sample_id)
            camp_name = ""
            if sample_obj and sample_obj.get("campaign_id"):
                camp = storage.get_campaign(conn, sample_obj["campaign_id"])
                if camp:
                    camp_name = camp.get("name", "")
            b_name = sample_brands[0]["brand"] if sample_brands else "не определён"
            in_t = "да" if (sample_brands and sample_brands[0].get("in_target")) else "нет"
            techs = sorted(list({f["technique"] for f in sample_findings}))
            r_codes = [s.get("signature") or s.get("value") or "" for s in sample_sigs if s.get("kind") == "reason_code"]
            r_codes = [c for c in r_codes if c]
            key_hashes = [a.get("sha256") for a in artifacts if a.get("sha256")][:5]
            conf = 0.9 if techs else 0.5
            camp_line = f"- Кампания: {camp_name}\n" if camp_name else ""
            verdict = f"""## Threat Intelligence Profile
- Имитируемый бренд: {b_name}
- Принадлежность к целевому списку (in_target): {in_t}
- Доменное несоответствие: {"да" if b_name != "не определён" else "нет"}
- Техники: {", ".join(techs) if techs else "не зафиксированы"}
{camp_line}- Хэши ключевых артефактов: {", ".join(key_hashes) if key_hashes else "нет"}
- Reason codes: {", ".join(r_codes) if r_codes else "SUSPICIOUS_SAMPLE"}
- Уверенность: {conf}
"""
        report_path = ARTIFACTS_DIR / task_id / "analyst_report.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(verdict, encoding="utf-8")
        rmd5, rsha = _hash_file(report_path)
        storage.add_artifact(conn, sample_id, "analyst_report", str(report_path),
                             rmd5, rsha, {"source": "analyst_agent"})

        storage.set_sample_status(conn, sample_id, "analyzed")
        conn.commit()

        report = storage.full_report(conn, sample_id)
        return {
            "ok": True,
            "sample_id": sample_id,
            "report": report,
            "collector": {
                "result": collector_result.get("result", ""),
                "steps": len(collector_result["trace"]),
                "files_registered": len(fin["added"]),
            },
            "analyst": {
                "result": verdict,
                "steps": len(analyst_result["trace"]),
                "report_path": str(report_path),
            },
        }
    except Exception as e:
        conn.rollback()
        return {"ok": False, "error": f"agent pipeline error: {e}"}
    finally:
        conn.close()


# Алиас для явного указания двух-агентной архитектуры
run_two_agent_pipeline = run_agent_pipeline
