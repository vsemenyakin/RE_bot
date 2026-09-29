#!/usr/bin/env python3
"""Замер быстродействия защищаемого бинаря на живой Raspberry Pi.

Копирует бинарь+зависимости и скрипт бенчмарка (truth/tools/bench.sh) на Pi,
гоняет его N раз, парсит throughput (fps) из bench_summary.txt и возвращает
медиану (плюс все прогоны, min/max, разброс) вместе с метаданными для сравнимости.

Throughput имеет смысл только на реальном железе -> Pi обязателен (RE_PI_* в .env).
Инструмент замера один: SSH/копирование переиспользуем из agent.PiDevice.

    python bench.py                       # параметры из bench_args.txt
    python bench.py --reps 3 --dist       # переопределить с CLI

Как функция (для bench_regression.py):
    from bench import run_bench
    result = run_bench(sample_dir=..., bench_script=..., reps=..., force=..., dist=...)
"""
import argparse
import hashlib
import re
import shlex
import statistics
import sys
from datetime import datetime
from pathlib import Path

from agent import PiDevice  # переиспользуем SSH/копирование, не плодим второй клиент

HERE = Path(__file__).resolve().parent

# Файлы, которые НЕ могут быть анализируемым бинарём (зависимости/данные).
_DEP_SUFFIXES = {".so", ".onnx", ".krw"}
_ELF_MAGIC = b"\x7fELF"


def load_bench_args(path):
    """bench_args.txt -> dict {ключ: значение}. Пустые значения допустимы."""
    conf = {}
    p = Path(path)
    if not p.is_file():
        return conf
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, _, val = line.partition("=")
        conf[key.strip()] = val.strip()
    return conf


def _as_bool(val, default=False):
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == _ELF_MAGIC
    except OSError:
        return False


def detect_binary_and_clip(sample_dir, binary_name=None, clip_name=None):
    """Вариант A: определяем бинарь и клип из содержимого sample-dir.
      клип   = единственный *.krw;
      бинарь = единственный ELF-файл, не являющийся зависимостью (.so/.onnx/.krw).
    Оверрайды binary_name/clip_name имеют приоритет (на случай неоднозначности)."""
    sd = Path(sample_dir)
    if not sd.is_dir():
        sys.exit(f"[!] нет каталога с образцом: {sd}")
    files = [f for f in sorted(sd.iterdir()) if f.is_file()]

    # --- клип ---
    if clip_name:
        clip = sd / clip_name
        if not clip.is_file():
            sys.exit(f"[!] задан clip-name={clip_name}, но файла нет в {sd}")
    else:
        krw = [f for f in files if f.suffix.lower() == ".krw"]
        if len(krw) != 1:
            sys.exit(f"[!] в {sd} найдено *.krw: {len(krw)} (ожидался ровно 1). "
                     f"Задай clip-name в bench_args.txt.")
        clip = krw[0]

    # --- бинарь ---
    if binary_name:
        binary = sd / binary_name
        if not binary.is_file():
            sys.exit(f"[!] задан binary-name={binary_name}, но файла нет в {sd}")
    else:
        cand = [f for f in files
                if f.suffix.lower() not in _DEP_SUFFIXES and _is_elf(f)]
        if len(cand) != 1:
            names = ", ".join(f.name for f in cand) or "(нет)"
            sys.exit(f"[!] в {sd} ELF-кандидатов на бинарь: {len(cand)} [{names}] "
                     f"(ожидался ровно 1). Задай binary-name в bench_args.txt.")
        binary = cand[0]
    return binary, clip


def _cargo_version(cargo_path):
    """Версия бинаря из [package] в Cargo.toml (как на атаке). '' если не нашли."""
    p = Path(cargo_path)
    if not p.is_file():
        return ""
    in_pkg = False
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s.startswith("["):
            in_pkg = s == "[package]"
            continue
        if in_pkg:
            m = re.match(r'version\s*=\s*"([^"]+)"', s)
            if m:
                return m.group(1)
    return ""


def _parse_summary(text):
    """bench_summary.txt -> {throughput, frames, wall, oracle}. None-поля, если не
    распозналось. throughput -- число перед 'fps'."""
    def find(pat, cast):
        m = re.search(pat, text)
        try:
            return cast(m.group(1)) if m else None
        except (ValueError, TypeError):
            return None
    return {
        "throughput": find(r'throughput:\s*([\d.]+)', float),
        "frames": find(r'frames:\s*(\d+)', int),
        "wall": find(r'wall:\s*([\d.]+)', float),
        "oracle": find(r'oracle:\s*(?:sha256\s*)?([0-9a-fA-F]{16,})', str),
    }


def _pi_id(pi):
    """Идентификатор Pi из /proc/cpuinfo (Model + Serial) -- разное железо
    несравнимо по throughput. Fallback -- hostname."""
    code, out = pi.exec("cat /proc/cpuinfo", timeout=15, in_workdir=False)
    model = serial = None
    if code == 0:
        for line in out.splitlines():
            if line.lower().startswith("model") and ":" in line:
                model = line.split(":", 1)[1].strip()
            elif line.lower().startswith("serial") and ":" in line:
                serial = line.split(":", 1)[1].strip()
    if model or serial:
        return f"{model or '?'}|serial:{serial or '?'}"
    code, out = pi.exec("hostname", timeout=15, in_workdir=False)
    return f"host:{out.strip()}" if code == 0 else "unknown"


def run_bench(sample_dir="./samples", bench_script="./truth/tools/bench.sh",
              reps=5, force=False, dist=False, binary_name=None, clip_name=None,
              cargo="./truth/Cargo.toml"):
    """Гоняет бенчмарк на Pi reps раз. Возвращает dict с медианой throughput и
    метаданными (ключ сравнимости + сигналы валидности). ok=False -> замер не
    состоялся (нет ни одного успешного прогона), точку данных писать нельзя."""
    sample_dir = (HERE / sample_dir).resolve() if not Path(sample_dir).is_absolute() else Path(sample_dir)
    bench_script = (HERE / bench_script).resolve() if not Path(bench_script).is_absolute() else Path(bench_script)
    if not bench_script.is_file():
        sys.exit(f"[!] нет скрипта бенчмарка: {bench_script}")

    binary, clip = detect_binary_and_clip(sample_dir, binary_name, clip_name)
    version = _cargo_version((HERE / cargo) if not Path(cargo).is_absolute() else Path(cargo))
    clip_sha = _sha256_file(clip)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    from dotenv import load_dotenv
    load_dotenv(HERE / ".env")
    pi = PiDevice.from_env(f"bench-{ts}")
    if pi is None:
        sys.exit("[!] RE_PI_HOST не задан -- бенчмарк требует живой Pi (см. .env). "
                 "Без Pi throughput мерить негде.")

    print(f"[i] бинарь: {binary.name} v{version or '?'} | клип: {clip.name} "
          f"(sha {clip_sha[:12]}) | dist={dist} force={force} reps={reps}")
    pi.connect()
    pi_id = _pi_id(pi)
    print(f"[i] Pi: {pi_id}")

    base = "bench"
    reps_data, throughputs = [], []
    try:
        # Разворачиваем bench/ на Pi (внутри рабочего каталога PiDevice). Скрипт
        # кладём в bench/tools/: bench.sh на старте делает `cd $(dirname $0)/..`,
        # поэтому из tools/ он попадает ровно в bench/ -- и относительный --out
        # (который он НЕ переякоривает) ложится в bench/results, как и ждём.
        pi.exec(f"rm -rf {base} && mkdir -p {base}/samples {base}/results {base}/tools",
                timeout=30)
        for f in sorted(sample_dir.iterdir()):
            if f.is_file():
                pi.push(f, remote_name=f"{base}/samples/{f.name}")
        pi.push(bench_script, remote_name=f"{base}/tools/bench.sh")

        # LD_LIBRARY_PATH -> samples: бинарь dlopen-ит libonnxruntime.so, а bench.sh
        # запускает его без пути к библиотекам. $PWD здесь = <workdir>/bench.
        force_prefix = "FORCE=1 " if force else ""
        dist_flag = " --dist" if dist else ""
        cmd = (f"cd {base} && LD_LIBRARY_PATH=\"$PWD/samples\" {force_prefix}"
               f"bash ./tools/bench.sh "
               f"--path ./samples/{shlex.quote(binary.name)} "
               f"--clip ./samples/{shlex.quote(clip.name)} "
               f"--out ./results{dist_flag}")

        for i in range(1, int(reps) + 1):
            print(f"[i] прогон {i}/{reps} ...", flush=True)
            code, out = pi.exec(cmd, timeout=1200)
            rcode, summary = pi.exec(f"cat {base}/results/bench_summary.txt", timeout=15)
            if rcode != 0:
                print(f"    [!] прогон {i}: нет bench_summary.txt (код bench.sh {code}). "
                      f"Возможно, сработал предохранитель (нужен force-benchmarking?).")
                print("    " + (out.strip()[-300:] or "(пустой вывод)"))
                continue
            parsed = _parse_summary(summary)
            if parsed["throughput"] is None:
                print(f"    [!] прогон {i}: не распарсил throughput из отчёта.")
                continue
            reps_data.append(parsed)
            throughputs.append(parsed["throughput"])
            print(f"    throughput={parsed['throughput']} fps, frames={parsed['frames']}, "
                  f"wall={parsed['wall']} s")

        # Ни одного успеха -> bench.sh прячет stderr бинаря (2>/dev/null), поэтому
        # запускаем бинарь НАПРЯМУЮ с видимым stderr: сразу видно 'missing library'
        # против 'не та сборка/usage'. Делаем до очистки bench/.
        if not throughputs:
            diag = (f"cd {base} && LD_LIBRARY_PATH=\"$PWD/samples\" "
                    f"./samples/{shlex.quote(binary.name)} ./samples/{shlex.quote(clip.name)}; "
                    f"echo \"rc=$?\"")
            _, dout = pi.exec(diag, timeout=180)
            print("[i] диагностика (прямой запуск бинаря, stderr виден):")
            tail = dout.strip().splitlines()[-20:] or ["(пусто)"]
            print("    " + "\n    ".join(tail))
    finally:
        pi.exec(f"rm -rf {base}", timeout=30)
        pi.close()

    if not throughputs:
        print("[!] ни один прогон не дал результата -- замер НЕ состоялся, точку не пишем.")
        return {"ok": False, "reps_requested": int(reps), "reps_ok": 0}

    # frames/oracle должны быть стабильны между прогонами (тот же бинарь+клип).
    frames_set = {d["frames"] for d in reps_data if d["frames"] is not None}
    oracle_set = {d["oracle"] for d in reps_data if d["oracle"]}
    if len(frames_set) > 1:
        print(f"[!] ВНИМАНИЕ: frames расходятся между прогонами: {sorted(frames_set)}")
    if len(oracle_set) > 1:
        print(f"[!] ВНИМАНИЕ: oracle-sha расходится между прогонами -- недетерминизм?")

    median = round(statistics.median(throughputs), 3)
    result = {
        "ok": True,
        "throughput_median": median,
        "throughput_all": throughputs,
        "throughput_min": min(throughputs),
        "throughput_max": max(throughputs),
        "throughput_spread": round(max(throughputs) - min(throughputs), 3),
        "reps_requested": int(reps),
        "reps_ok": len(throughputs),
        # --- ключ сравнимости ---
        "dist": bool(dist),
        "force_benchmarking": bool(force),
        "clip": clip.name,
        "clip_sha": clip_sha,
        "frames": next(iter(frames_set)) if len(frames_set) == 1 else None,
        "pi_id": pi_id,
        # --- контекст / валидность ---
        "binary": binary.name,
        "version": version,
        "oracle_sha": next(iter(oracle_set)) if len(oracle_set) == 1 else None,
        "timestamp": ts,
    }
    print(f"[+] throughput МЕДИАНА={median} fps  (min {result['throughput_min']} / "
          f"max {result['throughput_max']}, разброс {result['throughput_spread']}, "
          f"успешно {result['reps_ok']}/{result['reps_requested']})")
    return result


def _params_from(conf, opts):
    """Сводит параметры: bench_args.txt -> CLI-оверрайды."""
    def pick(cli, key, default):
        return cli if cli is not None else conf.get(key, default)
    return dict(
        sample_dir=pick(opts.sample_dir, "sample-dir", "./samples"),
        bench_script=pick(opts.bench_script_path, "bench-script-path", "./truth/tools/bench.sh"),
        reps=int(pick(opts.reps, "reps", 5)),
        force=_as_bool(opts.force if opts.force is not None else conf.get("force-benchmarking"), False),
        dist=_as_bool(opts.dist if opts.dist is not None else conf.get("dist"), False),
        binary_name=conf.get("binary-name") or None,
        clip_name=conf.get("clip-name") or None,
    )


def build_parser():
    ap = argparse.ArgumentParser(description="Замер быстродействия бинаря на Pi")
    ap.add_argument("--args", default=str(HERE / "bench_args.txt"),
                    help="файл аргументов (по умолчанию bench_args.txt рядом со скриптом)")
    ap.add_argument("--sample-dir", default=None)
    ap.add_argument("--bench-script-path", default=None)
    ap.add_argument("--reps", type=int, default=None)
    ap.add_argument("--dist", dest="dist", action="store_const", const="true", default=None)
    ap.add_argument("--force-benchmarking", dest="force", action="store_const",
                    const="true", default=None)
    return ap


def main():
    opts = build_parser().parse_args()
    conf = load_bench_args(opts.args)
    params = _params_from(conf, opts)
    result = run_bench(**params)
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\n[прервано пользователем]")
