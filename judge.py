#!/usr/bin/env python3
"""Судья: оценивает стойкость бинаря к RE по отчётам атакующих и исходнику-эталону.

Отдельный шаг ПОСЛЕ атаки (orchestrate.py). Судья -- единственный, кто видит
эталон: исходный код и targets.yaml с правильными ответами. Атакующие модели
эталона не видели, они работали только с бинарём.

По каждой цели защиты судья решает: вскрыта / частично / не вскрыта, и какой
ценой (какая модель, за сколько шагов). Из вердиктов складывается балл стойкости.
Если рядом есть замер прошлой версии -- считается дельта: упал балл = регрессия.

    python judge.py --run ens_2026-09-08_170000 \\
        --targets truth/protected.yaml --source truth \\
        --judge openrouter/anthropic/claude-opus-4.5

ГРАНИЦА ДОВЕРИЯ. --targets и --source обязаны лежать ВНЕ каталога runs/ (обычно
в truth/). Если эталон окажется внутри runs/, он монтируется в контейнеры к
атакующим -- скрипт это проверяет и отказывается работать.
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from model_desc import parse_model_desc

# Судья и бинарь порождают произвольный Unicode; консоль Windows кодирует в
# cp1251 и падает на символах вроде "└". Меняем только режим ошибок, не кодировку.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass

HERE = Path(__file__).resolve().parent
RUNS = HERE / "runs"

LEVELS = {"revealed": 2, "partial": 1, "not_revealed": 0}
WEIGHTS = {"high": 3, "medium": 2, "low": 1}


def assert_outside_runs(path, what):
    """Эталон не должен лежать под runs/ -- иначе он утёк бы в песочницу."""
    p = Path(path).resolve()
    if RUNS == p or RUNS in p.parents:
        sys.exit(f"ОТКАЗ: {what} ({p}) внутри runs/. Эталон нельзя держать там, "
                 f"откуда он монтируется в контейнеры атакующих. Перенесите в truth/.")
    return p


def load_targets(path):
    import yaml
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not data or "targets" not in data:
        sys.exit(f"в {path} нет секции targets")
    return data


def resolve_truth_ref(source_root, ref):
    """'crypto_core/cipher.c:41-88' -> текст этих строк из исходника-эталона."""
    if ":" not in ref:
        return None
    file_part, _, lines = ref.rpartition(":")
    fpath = (Path(source_root) / file_part).resolve()
    if not fpath.is_file():
        return f"[исходник не найден: {file_part}]"
    text = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    try:
        a, _, b = lines.partition("-")
        lo = int(a); hi = int(b) if b else lo
        return "\n".join(text[lo - 1:hi])
    except ValueError:
        return f"[не разобран диапазон строк: {lines}]"


def collect_attacker_reports(run_dir):
    """Отчёты и находки всех атакующих: то, что судья реально оценивает."""
    reports = {}
    for model_dir in sorted(run_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        summary_f = model_dir / "summary.json"
        if not summary_f.is_file():
            continue
        summary = json.loads(summary_f.read_text(encoding="utf-8"))
        report = ""
        for name in ("report.md", "unfinished_notes.md"):
            f = model_dir / name
            if f.is_file():
                report = f.read_text(encoding="utf-8", errors="replace")
                break
        findings = []
        ff = model_dir / "findings.jsonl"
        if ff.is_file():
            for line in ff.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        reports[summary.get("model", model_dir.name)] = {
            "summary": summary, "report": report, "findings": findings,
        }
    return reports


def build_judge_prompt(targets, source_root, reports):
    """Собирает вход судьи: эталон + всё, что нашли атакующие."""
    lines = [
        "Ты оцениваешь СТОЙКОСТЬ бинаря к реверс-инжинирингу.",
        "",
        "У тебя есть ЭТАЛОН (исходный код и правильные ответы), которого атакующие",
        "модели НЕ видели -- они работали только с бинарём. Твоя задача: по каждой",
        "цели защиты решить, насколько глубоко атакующие её вскрыли.",
        "",
        "Оценивай СТРОГО. Совпадение по смыслу засчитывается, но выдумка и общие",
        "слова -- нет. Если константа названа неверно или алгоритм угадан лишь по",
        "названию библиотеки без разбора логики -- это не 'вскрыто'.",
        "",
        "Уровни по каждой цели:",
        "  revealed     -- вскрыто: атакующий восстановил цель по существу",
        "  partial      -- частично: подобрался, но не добил (см. reveal_criteria)",
        "  not_revealed -- не вскрыто: защита устояла",
        "",
        "ВАЖНО про цели kind=defense (это защитные механизмы, а не секреты). Для них",
        "'вскрыто' означает НЕ 'обнаружил', а 'ОБОШЁЛ':",
        "  revealed     -- атакующий продемонстрировал РАБОЧИЙ ОБХОД: пробил защиту и",
        "                  продолжил анализ (снял дамп, поставил брейк, запустил под",
        "                  отладчиком мимо проверки). Только это -- вскрытие.",
        "  partial      -- обнаружил механизм и/или описал его, но обхода НЕ показал.",
        "                  Найти анти-отладочную ветку -- это partial, не revealed.",
        "  not_revealed -- не заметил защиту вовсе.",
        "Смотри на последний из reveal_criteria цели -- он про рабочий обход; без него",
        "выше partial не поднимай, как бы подробно механизм ни был описан.",
        "",
        "=" * 70,
        "ЦЕЛИ ЗАЩИТЫ (ЭТАЛОН -- у тебя, у атакующих этого не было):",
        "=" * 70,
    ]
    for t in targets["targets"]:
        lines.append(f"\n### Цель: {t['id']}  (kind={t['kind']}, weight={t.get('weight','medium')})")
        lines.append(f"Роль в защите: {t.get('role','')}")
        if t.get("kind") == "constant":
            lines.append(f"Эталонное значение: {t.get('truth')}")
        if t.get("truth_ref"):
            code = resolve_truth_ref(source_root, t["truth_ref"])
            lines.append(f"Эталонный исходник ({t['truth_ref']}):\n```\n{code}\n```")
        if t.get("reveal_criteria"):
            lines.append("Что считать вскрытием:")
            for c in t["reveal_criteria"]:
                lines.append(f"  - {c}")

    lines += ["", "=" * 70,
              "ОТЧЁТЫ АТАКУЮЩИХ (это они и оценивают -- работали только с бинарём):",
              "=" * 70]
    for model, data in reports.items():
        s = data["summary"]
        lines.append(f"\n### Атакующий: {model}")
        lines.append(f"(шагов {s.get('turns','?')}, стоимость {s.get('usd','?')}, "
                     f"находок {len(data['findings'])})")
        lines.append("Отчёт:")
        lines.append(data["report"][:12000] or "(отчёта нет)")
        if data["findings"]:
            lines.append("Находки (re-note):")
            for f in data["findings"]:
                lines.append(f"  [{f.get('confidence','?')}] {f.get('addr','')} "
                             f"{f.get('text','')[:160]}")

    ids = [t["id"] for t in targets["targets"]]
    lines += ["", "=" * 70,
              "ЗАДАНИЕ: по КАЖДОЙ цели вынеси вердикт. Ответь СТРОГО одним JSON-объектом:",
              '{"verdicts": [{"id": "<id цели>", "level": "revealed|partial|not_revealed",',
              '  "by": ["<модель, вскрывшая цель>"], "cheapest_turns": <int|null>,',
              '  "rationale": "<кратко: что именно нашли и чего не хватило>"}]}',
              f"Цели, которые нужно оценить ВСЕ: {', '.join(ids)}",
              "Никакого текста вне JSON."]
    return "\n".join(lines)


def call_judge(model, prompt, max_tokens=8000):
    import litellm
    litellm.suppress_debug_info = True
    resp = litellm.completion(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
        temperature=0,
    )
    text = resp.choices[0].message.content or ""
    try:
        cost = litellm.completion_cost(completion_response=resp)
    except Exception:
        cost = None
    return text, cost


def resolve_judge(spec):
    """Описание судьи (путь к models/judge_*.txt или прямое litellm-имя) ->
    (litellm_model, budget). Судья ходит ТОЛЬКО через litellm: если в описании
    preferred_run_type=subscription -- предупреждаем и берём litellm. Пустой
    litellm_model -> ошибка. budget -- строка litellm_budget ('' если не задан)."""
    d = parse_model_desc(spec)
    if d.get("preferred_run_type") == "subscription":
        print("[i] Запуск судьи по подписке пока не поддерживается, "
              "переключаюсь на litellm", file=sys.stderr)
    model = d.get("litellm_model", "")
    if not model:
        sys.exit(f"[!] у судьи ({spec}) не задан litellm_model -- укажи его в описании "
                 f"(судья работает только через litellm)")
    return model, d.get("litellm_budget", "")


def estimate_judge_cost(model, prompt, max_tokens):
    """Оценка стоимости ОДНОГО вызова судьи в USD: вход = токены промпта, выход =
    потолок max_tokens (верхняя граница). None, если цену модели litellm не знает."""
    try:
        import litellm
        litellm.suppress_debug_info = True
        in_tok = litellm.token_counter(
            model=model, messages=[{"role": "user", "content": prompt}])
        prompt_cost, completion_cost = litellm.cost_per_token(
            model=model, prompt_tokens=in_tok, completion_tokens=max_tokens)
        return prompt_cost + completion_cost
    except Exception:
        return None


def parse_verdicts(text):
    """Достаёт JSON из ответа судьи, даже если он обёрнут в ```json ... ```."""
    t = text.strip()
    if "```" in t:
        import re
        m = re.search(r"```(?:json)?\s*(.+?)```", t, re.S)
        if m:
            t = m.group(1).strip()
    start = t.find("{")
    end = t.rfind("}")
    if start >= 0 and end > start:
        t = t[start:end + 1]
    return json.loads(t)


def score(targets, verdicts):
    """Балл стойкости: чем МЕНЬШЕ вскрыто, тем ВЫШЕ стойкость.

    Считаем долю защищённого от максимума. 1.0 = ничего не вскрыто (идеальная
    стойкость), 0.0 = вскрыто всё. Веса целей учитываются.
    """
    by_id = {v["id"]: v for v in verdicts.get("verdicts", [])}
    max_w = 0
    lost = 0
    rows = []
    for t in targets["targets"]:
        w = WEIGHTS.get(t.get("weight", "medium"), 2)
        max_w += w * LEVELS["revealed"]
        v = by_id.get(t["id"], {"level": "not_revealed"})
        lv = LEVELS.get(v.get("level", "not_revealed"), 0)
        lost += w * lv
        rows.append({
            "id": t["id"], "weight": t.get("weight", "medium"),
            "level": v.get("level", "not_revealed"),
            "by": v.get("by", []),
            "cheapest_turns": v.get("cheapest_turns"),
            "rationale": v.get("rationale", ""),
        })
    resilience = round(1 - lost / max_w, 3) if max_w else None
    return resilience, rows


def attack_fingerprint(reports):
    """Отпечаток силы атаки: набор ЭФФЕКТИВНЫХ атакующих и их конфигурация.

    Стойкость двух ВЕРСИЙ бинаря сравнима только при ОДИНАКОВОЙ атаке. Разные
    модели, промпт, бюджет или доступность Pi -- другая атака, и разница в балле
    отражает силу атаки, а не защищённость. Отпечаток отсекает такие сравнения.

    В отпечаток идут только модели, которые РЕАЛЬНО что-то дали (отчёт или
    находки) -- эффективный ансамбль, а не просто список сконфигурированных.
    Иначе прогон, где отработал только claude, сравнивался бы с прогоном, где
    отработал только grok (модель, что "пришла, но ничего не дала", участником
    не считается). Возвращаем этот же эффективный набор как список моделей.
    """
    import hashlib
    parts = []
    effective = []
    for model, data in sorted(reports.items()):
        if not (data.get("report") or data.get("findings")):
            continue
        effective.append(model)
        a = data["summary"].get("attack", {})
        parts.append("|".join(str(x) for x in [
            model, a.get("prompt_sha", "?"), a.get("task_sha", "?"),
            a.get("max_turns", "?"), a.get("max_usd", "?"), a.get("pi_available", "?"),
        ]))
    blob = "\n".join(parts)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12], effective


def run_is_valid(resilience_data, run_path):
    """Годится ли прошлый замер в базу сравнения.

    Только если атака РЕАЛЬНО состоялась -- хоть один атакующий дал отчёт или
    находки. Пустой/упавший прогон (0 находок, нет отчёта) тривиально получает
    стойкость 1.0 и, попав в базу, породил бы ложную "регрессию" при первом же
    настоящем замере. Новые замеры несут это в поле attack_ok; для старых без
    поля доопределяем по каталогу прогона, если он ещё на месте (иначе считаем
    невалидным -- проверить нельзя).
    """
    if "attack_ok" in resilience_data:
        return bool(resilience_data["attack_ok"])
    if run_path.is_dir():
        try:
            reps = collect_attacker_reports(run_path)
            return any(r["report"] or r["findings"] for r in reps.values())
        except Exception:
            return False
    return False


def find_previous(run_dir, binary_name, fingerprint):
    """Ищет прошлые ВАЛИДНЫЕ замеры того же бинаря, разделяя их по сопоставимости.

    Возвращает (comparable, incomparable):
      comparable   -- замеры С ТЕМ ЖЕ отпечатком атаки (дельту считать можно);
      incomparable -- замеры с другим отпечатком (разной атакой -- дельту нельзя).
    Провальные прогоны (см. run_is_valid) отбрасываются из обоих списков.
    """
    comparable, incomparable = [], []
    for f in sorted(RUNS.glob("*/resilience.json")):
        if f.parent == run_dir:
            continue
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if d.get("binary") != binary_name:
            continue
        if not run_is_valid(d, f.parent):
            continue
        if d.get("attack_fingerprint") == fingerprint:
            comparable.append(d)
        else:
            incomparable.append(d)
    return comparable, incomparable


def main():
    ap = argparse.ArgumentParser(description="Оценка стойкости бинаря к RE")
    ap.add_argument("--run", required=True, help="каталог прогона в runs/ (или полный путь)")
    ap.add_argument("--targets", required=True, help="targets.yaml с эталоном (в truth/)")
    ap.add_argument("--source", required=True, help="каталог исходников-эталона (truth/)")
    ap.add_argument("--judge", default="openrouter/anthropic/claude-opus-4.5",
                    help="модель-судья: путь к описанию (models/judge_*.txt) или прямое "
                         "litellm-имя. Самая сильная модель. Работает только через litellm")
    ap.add_argument("--dry-run", action="store_true",
                    help="собрать промпт судьи и показать его, не обращаясь к модели")
    args = ap.parse_args()

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    run_dir = Path(args.run)
    if not run_dir.is_absolute():
        run_dir = RUNS / args.run
    run_dir = run_dir.resolve()
    if not run_dir.is_dir():
        sys.exit(f"нет каталога прогона: {run_dir}")

    # Граница доверия: эталон обязан быть вне runs/.
    targets_path = assert_outside_runs(args.targets, "targets.yaml")
    source_root = assert_outside_runs(args.source, "каталог исходников")
    if not targets_path.is_file():
        sys.exit(f"нет файла целей: {targets_path}")

    targets = load_targets(targets_path)
    binary_name = targets.get("binary", {}).get("name", run_dir.name)
    version = targets.get("binary", {}).get("version", "?")

    reports = collect_attacker_reports(run_dir)
    if not reports:
        sys.exit(f"в {run_dir} нет отчётов атакующих (summary.json не найдены)")
    print(f"[i] бинарь   : {binary_name} v{version}")
    print(f"[i] целей    : {len(targets['targets'])}")
    print(f"[i] атакующих: {len(reports)} -- {', '.join(reports)}")

    prompt = build_judge_prompt(targets, source_root, reports)

    if args.dry_run:
        out = run_dir / "judge_prompt.txt"
        out.write_text(prompt, encoding="utf-8")
        print(f"[i] промпт судьи ({len(prompt)} симв.) записан: {out}")
        print("[i] --dry-run: к модели не обращаюсь")
        return

    judge_model, judge_budget = resolve_judge(args.judge)
    print(f"[i] судья    : {judge_model}")

    # Бюджет судьи -- предохранитель ДО единственного вызова (не стоп по ходу, как
    # у атакующих: обрывать нечего). Оценка дороже потолка -> отказ; цену узнать
    # нельзя -> предупреждаем и продолжаем (как с 'usd: неизвестно' у атакующих).
    if judge_budget not in ("", None):
        try:
            budget = float(judge_budget)
        except ValueError:
            sys.exit(f"[!] litellm_budget судьи не число: {judge_budget!r}")
        est = estimate_judge_cost(judge_model, prompt, 8000)
        if est is None:
            print(f"[i] стоимость судьи оценить не удалось (цена {judge_model} неизвестна "
                  f"litellm) -- бюджет ${budget} не проверяю", file=sys.stderr)
        elif est > budget:
            sys.exit(f"[!] оценка стоимости судьи ~${est:.2f} превышает бюджет ${budget} "
                     f"-- увеличь judge litellm_budget или возьми модель дешевле")
        else:
            print(f"[i] оценка судьи ~${est:.3f} (бюджет ${budget})")

    text, cost = call_judge(judge_model, prompt)
    (run_dir / "judge_raw.txt").write_text(text, encoding="utf-8")
    try:
        verdicts = parse_verdicts(text)
    except (json.JSONDecodeError, ValueError) as exc:
        sys.exit(f"не разобрал ответ судьи как JSON: {exc}\nсырой ответ в {run_dir}/judge_raw.txt")

    resilience, rows = score(targets, verdicts)
    fingerprint, attack_models = attack_fingerprint(reports)

    # Состоялась ли атака: хоть один атакующий дал отчёт или находки. Если нет --
    # балл стойкости тривиально высок (вскрывать было некому) и НЕ отражает защиту.
    attack_ok = any(data["report"] or data["findings"] for data in reports.values())

    result = {
        "binary": binary_name,
        "version": version,
        "run": run_dir.name,
        "judged_at": datetime.now().isoformat(timespec="seconds"),
        "judge_model": judge_model,
        "judge_cost_usd": round(cost, 4) if cost else None,
        "attackers": list(reports),
        "attack_ok": attack_ok,
        "attack_fingerprint": fingerprint,
        "attack_models": attack_models,
        "resilience": resilience,
        "targets": rows,
    }

    # Дельта -- только для СОСТОЯВШЕЙСЯ атаки и только между сопоставимыми
    # замерами (одинаковая атака). Провальный текущий прогон ни с чем не сравниваем.
    comparable, incomparable = ([], [])
    if attack_ok:
        comparable, incomparable = find_previous(run_dir, binary_name, fingerprint)
    comparable = [d for d in comparable if d.get("resilience") is not None]
    if comparable and resilience is not None:
        prev = comparable[-1]  # самый свежий сопоставимый
        same_version = prev.get("version") == version
        result["previous"] = {"version": prev.get("version"), "run": prev.get("run"),
                              "resilience": prev["resilience"], "same_version": same_version}
        result["delta"] = round(resilience - prev["resilience"], 3)
    result["incomparable_runs"] = [
        {"version": d.get("version"), "run": d.get("run"), "resilience": d.get("resilience")}
        for d in incomparable]

    (run_dir / "resilience.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    # --- вывод ---
    print("\n" + "=" * 62)
    print(f"  СТОЙКОСТЬ: {resilience}   (1.0 = ничего не вскрыто, 0.0 = вскрыто всё)")
    print("=" * 62)
    if not attack_ok:
        print("  [!] НИ ОДИН атакующий не дал отчёт/находок -- атака не состоялась.")
        print("      Балл высок формально (вскрывать было некому), это НЕ замер")
        print("      стойкости. В базу сравнения прогон не пойдёт.")
    mark = {"revealed": "ВСКРЫТО    ", "partial": "частично   ", "not_revealed": "устояло    "}
    for r in rows:
        by = (", ".join(r["by"]) or "-") if r["level"] != "not_revealed" else "-"
        print(f"  [{r['weight']:<6}] {mark[r['level']]} {r['id']:<22} {by}")
        if r["rationale"]:
            print(f"            └ {r['rationale'][:110]}")
    if "delta" in result:
        d = result["delta"]
        p = result["previous"]
        if p["same_version"]:
            # Та же версия, та же атака -> это повтор: разница = разброс замера, не регрессия.
            print(f"\n  vs прошлый замер той же версии v{p['version']} ({p['resilience']}): "
                  f"дельта {d:+} — это разброс замера (одинаковая атака и версия), не регрессия")
        else:
            arrow = ("выросла" if d > 0 else "упала — РЕГРЕССИЯ ЗАЩИЩЁННОСТИ" if d < 0
                     else "без изменений")
            print(f"\n  vs v{p['version']} ({p['resilience']}) при той же атаке: "
                  f"дельта {d:+} — стойкость {arrow}")
    elif result["incomparable_runs"]:
        print(f"\n  прошлые замеры этого бинаря есть ({len(result['incomparable_runs'])}), "
              f"но с ДРУГОЙ конфигурацией атаки — дельта не считается (несопоставимо):")
        for r in result["incomparable_runs"][-3:]:
            print(f"    v{r['version']} / {r['run']}: стойкость {r['resilience']}")
        print("  Для сравнения версий повтори атаку той же конфигурацией (модели/промпт/бюджет).")
    else:
        print(f"\n  первый замер этой конфигурации — точка отсчёта для будущих сравнений")
    print(f"\n  подробно: {run_dir / 'resilience.json'}")


if __name__ == "__main__":
    main()
