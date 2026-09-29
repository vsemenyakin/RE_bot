#!/usr/bin/env python3
"""Регрессии быстродействия: замерить throughput на Pi и сравнить с прошлым
сопоставимым замером.

Гоняет bench.run_bench(), пишет результат в runs/bench/<дата_время>.json и, если
есть прошлый СОПОСТАВИМЫЙ замер, показывает изменение throughput.

Сопоставимость (по аналогии с attack fingerprint): дельта throughput -- настоящая
регрессия, только если совпадают dist + клип (sha) + Pi + force-benchmarking +
frames. Версия -- ОСЬ: та же версия = повтор/разброс, другая = замер регрессии.
oracle-sha в ключ не входит, но при расхождении предупреждаем: бинарь считает
ДРУГОЙ результат -> сравнивать throughput бессмысленно.

Пока ОПИСАТЕЛЬНО: печатаем old->new, дельту и %, без авто-вердикта "регрессия"
(коридор шума на троттлящем Pi нужно намерить на нескольких прогонах).

    python bench_regression.py
"""
import json
import sys
from pathlib import Path

import bench

HERE = Path(__file__).resolve().parent
BENCH_RUNS = HERE / "runs" / "bench"

# Поля, по совпадению которых замеры сопоставимы (версия сюда НЕ входит -- это ось).
KEY_FIELDS = ("dist", "clip_sha", "pi_id", "force_benchmarking", "frames")


def _key(rec):
    return tuple(rec.get(f) for f in KEY_FIELDS)


def find_previous(current):
    """Свежайший прошлый замер с тем же ключом сопоставимости. None, если нет."""
    if not BENCH_RUNS.is_dir():
        return None
    cur_key = _key(current)
    prev = []
    for f in sorted(BENCH_RUNS.glob("*.json")):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not rec.get("ok"):
            continue
        if rec.get("timestamp") == current.get("timestamp"):
            continue
        if _key(rec) == cur_key:
            prev.append(rec)
    prev.sort(key=lambda r: r.get("timestamp", ""))
    return prev[-1] if prev else None


def main():
    conf = bench.load_bench_args(HERE / "bench_args.txt")
    params = dict(
        sample_dir=conf.get("sample-dir", "./samples"),
        bench_script=conf.get("bench-script-path", "./truth/tools/bench.sh"),
        reps=int(conf.get("reps", 5)),
        force=bench._as_bool(conf.get("force-benchmarking"), False),
        dist=bench._as_bool(conf.get("dist"), False),
        binary_name=conf.get("binary-name") or None,
        clip_name=conf.get("clip-name") or None,
    )

    result = bench.run_bench(**params)
    if not result.get("ok"):
        sys.exit("[!] замер не состоялся -- точку данных не пишем, сравнивать нечего.")

    BENCH_RUNS.mkdir(parents=True, exist_ok=True)
    out = BENCH_RUNS / f"{result['timestamp']}.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    prev = find_previous(result)

    print("\n" + "=" * 62)
    print(f"  БЫСТРОДЕЙСТВИЕ: {result['throughput_median']} fps (медиана)   "
          f"[бинарь {result['binary']} v{result['version'] or '?'}, "
          f"{'dist' if result['dist'] else 'не-dist'}]")
    print("=" * 62)

    if prev is None:
        print("  первый сопоставимый замер этой конфигурации -- точка отсчёта.")
    else:
        old, new = prev["throughput_median"], result["throughput_median"]
        delta = round(new - old, 3)
        pct = round(100.0 * delta / old, 2) if old else float("nan")
        same_version = prev.get("version") == result.get("version")
        kind = ("та же версия -> разброс замера (не регрессия)" if same_version
                else f"версия {prev.get('version') or '?'} -> {result.get('version') or '?'} -- замер регрессии")
        arrow = "быстрее" if delta > 0 else "МЕДЛЕННЕЕ" if delta < 0 else "без изменений"
        print(f"  vs {prev['timestamp']} ({old} fps): дельта {delta:+} fps ({pct:+}%), {arrow}")
        print(f"    {kind}")
        print(f"    разброс: сейчас {result['throughput_spread']} fps "
              f"(min {result['throughput_min']}/max {result['throughput_max']}), "
              f"тогда {prev.get('throughput_spread')} fps")
        if result.get("oracle_sha") and prev.get("oracle_sha") \
                and result["oracle_sha"] != prev["oracle_sha"]:
            print("    [!] oracle-sha ИЗМЕНИЛСЯ -- бинарь считает другой результат; "
                  "сравнение throughput невалидно (иная работа, а не скорость).")

    print(f"\n  подробно: {out}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\n[прервано пользователем]")
