#!/usr/bin/env python3
"""RE-сессия в один запуск: цели -> атака ансамблем -> оценка судьёй.

Три шага цепочкой, аргументы атаки берутся из RE_args.txt рядом со скриптом:

  1. targets_gen.py  -- собрать targets.yaml из маркеров в исходниках (эталон)
  2. orchestrate.py  -- ансамбль моделей атакует бинарь в изолированной песочнице
  3. judge.py        -- судья сверяет отчёты с эталоном, считает стойкость

Имя прогона скрипт задаёт сам и передаёт оркестратору через --run-dir, поэтому
путь к отчёту известен заранее -- судью не нужно наводить парсингом чужого вывода.

    python run_RE.py                 # обычный запуск
    python run_RE.py --args my.txt   # другой файл аргументов
    python run_RE.py --skip-targets  # не пересобирать targets.yaml
"""
import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Ключи из RE_args, относящиеся к эталону, а не к атаке: в orchestrate не идут.
JUDGE_KEYS = {"source", "targets-out", "cargo"}
FLAG_KEYS = {"no-pi"}  # ключи-флаги без значения


def parse_args_file(path):
    """RE_args.txt -> dict. Значение может быть пустым (для флагов)."""
    conf = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            # строка-флаг без '='
            conf[line.strip()] = ""
            continue
        key, _, val = line.partition("=")
        conf[key.strip()] = val.strip()
    return conf


def run_step(name, cmd):
    print(f"\n{'=' * 64}\n[ЭТАП] {name}\n  {' '.join(cmd)}\n{'=' * 64}", flush=True)
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        sys.exit(f"\n[!] этап '{name}' завершился с ошибкой (код {proc.returncode}). "
                 f"Цепочка остановлена.")
    return proc


def main():
    ap = argparse.ArgumentParser(description="RE-сессия в один запуск")
    ap.add_argument("--args", default=str(HERE / "RE_args.txt"),
                    help="файл аргументов (по умолчанию RE_args.txt рядом со скриптом)")
    ap.add_argument("--skip-targets", action="store_true",
                    help="не пересобирать targets.yaml (использовать существующий)")
    ap.add_argument("--judge", default=None, help="модель-судья (иначе дефолт judge.py)")
    opts = ap.parse_args()

    args_path = Path(opts.args)
    if not args_path.is_file():
        sys.exit(f"нет файла аргументов: {args_path}")
    conf = parse_args_file(args_path)

    py = sys.executable
    source = conf.get("source", "truth")
    targets_out = conf.get("targets-out", "truth/protected.yaml")
    cargo = conf.get("cargo")

    # --- имя прогона: задаём сами, чтобы знать путь для судьи ---
    run_name = "ens_" + datetime.now().strftime("%Y-%m-%d_%H%M%S")
    run_dir = HERE / "runs" / run_name

    # === ЭТАП 1: цели из маркеров ===
    if not opts.skip_targets:
        cmd = [py, str(HERE / "targets_gen.py"), "--source", source, "--out", targets_out]
        if cargo:
            cmd += ["--cargo", cargo]
        run_step("генерация целей (targets_gen.py)", cmd)
    else:
        print("[i] --skip-targets: targets.yaml не пересобирается")
    if not Path(HERE / targets_out).is_file() and not Path(targets_out).is_file():
        sys.exit(f"нет файла целей: {targets_out} -- убери --skip-targets или создай его")

    # === ЭТАП 2: атака ансамблем ===
    # Имена ключей в файле аргументов бывают с подчёркиванием, флаги orchestrate --
    # с дефисом. Нормализуем: '_' -> '-' только в имени ключа (не в значении).
    cmd = [py, str(HERE / "orchestrate.py"), "--run-dir", str(run_dir)]
    for key, val in conf.items():
        if key in JUDGE_KEYS:
            continue
        flag = "--" + key.replace("_", "-")
        if key in FLAG_KEYS:
            cmd.append(flag)
        elif key == "deps":
            cmd += ["--deps"] + val.split()
        else:
            cmd += [flag, val]
    run_step("атака ансамблем (orchestrate.py)", cmd)

    # === ЭТАП 3: оценка судьёй ===
    cmd = [py, str(HERE / "judge.py"), "--run", str(run_dir),
           "--targets", targets_out, "--source", source]
    if opts.judge:
        cmd += ["--judge", opts.judge]
    run_step("оценка стойкости (judge.py)", cmd)

    res = run_dir / "resilience.json"
    print(f"\n[+] RE-сессия завершена.")
    print(f"    прогон:  {run_dir}")
    print(f"    итог:    {res}")


if __name__ == "__main__":
    main()
