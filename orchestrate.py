#!/usr/bin/env python3
"""Оркестратор: ансамбль моделей атакует один бинарь, оценивая его стойкость к RE.

Цель проекта -- не сверка моделей, а измерение, насколько глубоко удаётся вскрыть
защиту бинаря (константы, алгоритм), и отслеживание регрессий защищённости между
версиями. Много атакующих = шире фронт атаки: цель считается вскрытой, если её
взяла хоть одна модель.

Каждая модель работает в своей песочнице над своей копией бинаря, параллельно и
независимо. Их отчёты потом оценивает judge.py, сравнивая с исходником-эталоном.

ГРАНИЦА ДОВЕРИЯ. Этот скрипт запускает только АТАКУ. Он принципиально не знает ни
про исходный код, ни про targets.yaml -- эталон не должен попасть атакующим, иначе
замер стойкости обнуляется. В контейнеры уходит лишь бинарь (это делает agent.py).
Оценка -- отдельный шаг (judge.py) на хосте, после атаки.

    python orchestrate.py --sample samples/protected --budget-total 10 \\
        --models openrouter/anthropic/claude-opus-4.5,openrouter/x-ai/grok-4,\\
                 openrouter/qwen/qwen3-max,openrouter/google/gemini-2.5-pro
"""
import argparse
import concurrent.futures
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent


def parse_model_desc(spec):
    """Спецификация модели -> dict {name, litellm_model, subscription_model, id}.

    spec -- путь к файлу описания (models/claude.txt) ИЛИ прямое имя litellm-модели
    (обратная совместимость: openrouter/... трактуется как только-litellm).
    """
    p = Path(spec)
    if p.is_file():
        d = {"name": "", "litellm_model": "", "subscription_model": ""}
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            d[k.strip()] = v.strip().strip('"').strip("'")
        d["id"] = d.get("litellm_model") or d.get("subscription_model") or d.get("name") or spec
        return d
    return {"name": "", "litellm_model": spec, "subscription_model": "", "id": spec}


def label_for(desc):
    """Имя рабочего каталога -- ДОЛЖНО совпадать с label в agent.py (тот же приоритет)."""
    src = desc.get("litellm_model") or desc.get("subscription_model") or desc.get("name") or "model"
    return src.replace("/", "_").replace(":", "_")


def run_one(desc, sample, run_dir, budget, turns, prefer, extra_args, log_path):
    """Запускает agent.py для одной модели как подпроцесс. Возвращает (id, summary)."""
    cmd = [
        sys.executable, str(HERE / "agent.py"),
        "--sample", str(sample),
        "--run-dir", str(run_dir),
        "--max-usd", str(budget),
        "--max-turns", str(turns),
        "--prefer-run-type", prefer,
    ]
    if desc.get("name"):
        cmd += ["--model-name", desc["name"]]
    if desc.get("litellm_model"):
        cmd += ["--model", desc["litellm_model"]]
    if desc.get("subscription_model"):
        cmd += ["--subscription-model", desc["subscription_model"]]
    cmd += extra_args

    t0 = time.time()
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)

    summary_path = run_dir / label_for(desc) / "summary.json"
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    else:
        summary = {"model": desc["id"],
                   "stop_reason": f"agent.py не оставил summary (код {proc.returncode})"}
    summary["wall_seconds"] = round(time.time() - t0)
    summary["exit_code"] = proc.returncode
    return desc["id"], summary


def main():
    ap = argparse.ArgumentParser(description="Ансамблевая атака на бинарь")
    ap.add_argument("--sample", required=True, help="бинарь для атаки")
    ap.add_argument("--deps", nargs="*", default=[],
                    help="зависимости бинаря (библиотеки, данные) -- доступны атакующим")
    ap.add_argument("--models", required=True,
                    help="через запятую: пути к файлам описания моделей (models/claude.txt) "
                         "или прямые имена litellm-моделей")
    ap.add_argument("--preferred-models-run-type", choices=["litellm", "subscription"],
                    default="litellm",
                    help="предпочтительный маршрут для всех моделей (кто умеет)")
    ap.add_argument("--budget-total", type=float, default=10.0,
                    help="общий бюджет в $ (реальные деньги) на litellm-модели, делится "
                         "поровну между НИМИ; subscription-модели в делении не участвуют")
    ap.add_argument("--budget-per-model", type=float, default=None,
                    help="бюджет на litellm-модель (переопределяет деление budget-total)")
    ap.add_argument("--budget-claude-subscription", type=float, default=10.0,
                    help="лимит (API-эквивалент) для Claude по подписке -> --max-budget-usd. "
                         "Не реальные деньги: расход из лимитов Pro. ~75%% окна Opus ≈ 10")
    ap.add_argument("--max-turns", type=int, default=80)
    ap.add_argument("--parallel", type=int, default=3,
                    help="сколько моделей гнать одновременно (docker и API не любят перегруз)")
    ap.add_argument("--task", default=None,
                    help="формулировка атаки; по умолчанию берётся из agent.py")
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--no-pi", action="store_true")
    ap.add_argument("--label", default="", help="метка прогона (версия бинаря), идёт в манифест")
    args = ap.parse_args()

    sample = Path(args.sample).resolve()
    if not sample.is_file():
        sys.exit(f"нет такого файла: {sample}")

    specs = [m.strip() for m in args.models.split(",") if m.strip()]
    if not specs:
        sys.exit("не заданы модели")
    descs = [parse_model_desc(s) for s in specs]
    models = [d["id"] for d in descs]

    # Маршрут модели (для деления бюджета): subscription, если так предпочтено и
    # модель это умеет. Токен-свежесть тут не важна -- это про деление денег.
    def is_subscription(d):
        return (args.preferred_models_run_type == "subscription"
                and bool(d.get("subscription_model")))

    # budget-total (реальные деньги) делится только между LITELLM-моделями:
    # подписка реальных денег не тратит и бюджет у litellm не отбирает.
    litellm_descs = [d for d in descs if not is_subscription(d)]
    if litellm_descs:
        per_litellm = args.budget_per_model or round(args.budget_total / len(litellm_descs), 3)
    else:
        # Только подписочные модели -- делить budget-total не между кем.
        per_litellm = args.budget_per_model or 0.0

    def budget_for(d):
        if is_subscription(d):
            # Каждой подписочной модели -- свой лимит (у них разные окна/валюты).
            if d.get("name") == "claude":
                return args.budget_claude_subscription
            return per_litellm  # неизвестная подписочная модель -- запасной вариант
        return per_litellm

    run_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    run_dir = Path(args.run_dir).resolve() if args.run_dir else HERE / "runs" / f"ens_{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    extra = []
    if args.task:
        extra += ["--task", args.task]
    if args.no_pi:
        extra += ["--no-pi"]
    if args.deps:
        deps = [str(Path(d).resolve()) for d in args.deps]
        for d in deps:
            if not Path(d).is_file():
                sys.exit(f"нет файла зависимости: {d}")
        extra += ["--deps"] + deps

    print(f"[i] прогон     : {run_dir.name}")
    print(f"[i] бинарь     : {sample.name}")
    print(f"[i] моделей    : {len(descs)}, параллельно {args.parallel}")
    print(f"[i] маршрут    : предпочтительно {args.preferred_models_run_type}")
    for d in descs:
        route = "subscription" if is_subscription(d) else "litellm"
        kind = "лимит-подписки" if is_subscription(d) else "реальные $"
        print(f"[i]   {d['id'][:40]:<40} {route:<13} бюджет ${budget_for(d)} ({kind})")
    print()

    # Манифест пишем сразу, чтобы при обрыве было видно, что запускалось.
    manifest = {
        "run_id": run_id,
        "label": args.label,
        "sample": sample.name,
        "sample_bytes": sample.stat().st_size,
        "models": models,
        "preferred_run_type": args.preferred_models_run_type,
        "budget_per_litellm": per_litellm,
        "budget_claude_subscription": args.budget_claude_subscription,
        "max_turns": args.max_turns,
        "started": datetime.now().isoformat(timespec="seconds"),
        "results": {},
    }
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    results = {}
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
        futures = {
            pool.submit(run_one, d, sample, run_dir, budget_for(d), args.max_turns,
                        args.preferred_models_run_type, extra,
                        run_dir / f"{label_for(d)}.console.log"): d["id"]
            for d in descs
        }
        for fut in concurrent.futures.as_completed(futures):
            model, summary = fut.result()
            results[model] = summary
            # Обновляем манифест после каждой модели -- прогресс виден по ходу.
            manifest["results"] = results
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            report = "есть" if summary.get("report") else "НЕТ"
            print(f"[+] {model}")
            print(f"      находок {summary.get('findings', '?')}, отчёт {report}, "
                  f"шагов {summary.get('turns', '?')}, ${summary.get('usd', '?')}, "
                  f"кэш {summary.get('cache_hit_rate', '?')}")
            # Причину видно всегда, когда модель ничего не дала -- напр. протухший
            # токен подписки (её формирует сама модель в summary, мы лишь печатаем).
            sr = summary.get("stop_reason", "")
            if not summary.get("findings") and not summary.get("report") and sr:
                print(f"      причина: {sr}")

    manifest["finished"] = datetime.now().isoformat(timespec="seconds")
    manifest["wall_seconds"] = round(time.time() - t0)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    # Имя последнего прогона -- чтобы судью можно было запустить вручную без
    # выискивания каталога. run_RE.py путь и так знает (сам задал --run-dir).
    (run_dir.parent / "LAST_RUN.txt").write_text(run_dir.name, encoding="utf-8")

    # Сводка по прогону.
    total_usd = sum(r.get("usd", 0) for r in results.values() if isinstance(r.get("usd"), (int, float)))
    with_report = sum(1 for r in results.values() if r.get("report"))
    total_findings = sum(r.get("findings", 0) for r in results.values()
                         if isinstance(r.get("findings"), int))
    print("\n" + "=" * 60)
    print(f"  каталог      {run_dir}")
    print(f"  моделей      {len(models)}, с отчётом {with_report}")
    print(f"  находок      {total_findings} суммарно")
    print(f"  потрачено    ${round(total_usd, 3)}")
    print(f"  время        {manifest['wall_seconds']} c")
    print(f"\n  дальше: python judge.py --run {run_dir.name} "
          f"--targets <targets.yaml> --source <каталог исходников>")
    print("  (судья видит эталон; атакующие -- нет)")


if __name__ == "__main__":
    main()
