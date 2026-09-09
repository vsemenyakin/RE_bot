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


def label_for(model):
    return model.replace("/", "_").replace(":", "_")


def run_one(model, sample, run_dir, budget, turns, extra_args, log_path):
    """Запускает agent.py для одной модели как подпроцесс. Возвращает (model, summary)."""
    cmd = [
        sys.executable, str(HERE / "agent.py"),
        "--sample", str(sample),
        "--model", model,
        "--run-dir", str(run_dir),
        "--max-usd", str(budget),
        "--max-turns", str(turns),
    ] + extra_args

    t0 = time.time()
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)

    # summary.json пишет сам agent.py; читаем его как результат работы.
    summary_path = run_dir / label_for(model) / "summary.json"
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    else:
        summary = {"model": model,
                   "stop_reason": f"agent.py не оставил summary (код {proc.returncode})"}
    summary["wall_seconds"] = round(time.time() - t0)
    summary["exit_code"] = proc.returncode
    return model, summary


def main():
    ap = argparse.ArgumentParser(description="Ансамблевая атака на бинарь")
    ap.add_argument("--sample", required=True, help="бинарь для атаки")
    ap.add_argument("--deps", nargs="*", default=[],
                    help="зависимости бинаря (библиотеки, данные) -- доступны атакующим")
    ap.add_argument("--models", required=True,
                    help="список моделей через запятую (нотация LiteLLM)")
    ap.add_argument("--budget-total", type=float, default=10.0,
                    help="общий бюджet в $ на весь прогон, делится поровну между моделями")
    ap.add_argument("--budget-per-model", type=float, default=None,
                    help="бюджет на модель (переопределяет деление budget-total)")
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

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    if not models:
        sys.exit("не заданы модели")

    per_model = args.budget_per_model or round(args.budget_total / len(models), 3)

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
    print(f"[i] моделей    : {len(models)}, параллельно {args.parallel}")
    print(f"[i] бюджет     : ${per_model} на модель, ${round(per_model * len(models), 2)} всего")
    print(f"[i] модели     : {', '.join(models)}\n")

    # Манифест пишем сразу, чтобы при обрыве было видно, что запускалось.
    manifest = {
        "run_id": run_id,
        "label": args.label,
        "sample": sample.name,
        "sample_bytes": sample.stat().st_size,
        "models": models,
        "budget_per_model": per_model,
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
            pool.submit(run_one, m, sample, run_dir, per_model, args.max_turns,
                        extra, run_dir / f"{label_for(m)}.console.log"): m
            for m in models
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
