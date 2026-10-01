#!/usr/bin/env python3
"""Развёртывание frida на живой Raspberry Pi -- запускается с ХОСТА, ставит всё на
Pi по SSH (через agent.PiDevice, доступ из .env RE_PI_*).

Зачем: frida нужна атакующему для рантайм-инструментирования -- снять
зашифрованные-в-покое константы, которые декодируются только при исполнении (хук
декодеров / сайтов сравнения вместо грубого дампа RAM).

Ставим frida-tools ЛОКАЛЬНО на Pi (в venv), НЕ frida-server: атакующий исполняет
команды на самой Pi (pi_exec) и сидит в контейнере без сети, поэтому удалённый
сервер ему недоступен, а локальный CLI -- в самый раз.

    python install_frida.py                          # venv ~/re-frida, дефолтная версия
    python install_frida.py --frida-tools-version 13.7.1
    python install_frida.py --force                  # переустановить

Идемпотентно: если frida уже стоит в venv -- пропускает (если не --force). Установка
БЕЗ sudo (venv в $HOME). Реальное хукание требует ptrace -> запускать под sudo:
    sudo <venv>/bin/frida -f ./sample <clip> -l hook.js
"""
import argparse
import sys
from pathlib import Path

from agent import PiDevice  # переиспользуем SSH/доступ к Pi, не плодим второй клиент

HERE = Path(__file__).resolve().parent

# Пин на серию 13.x (frida core 16.x): зрелая, на PyPI есть готовые aarch64-колёса
# (сборка не нужна). Внутри серии берётся свежайшее. Строгий пин -- через аргумент.
DEFAULT_SPEC = "frida-tools==13.*"
DEFAULT_VENV = "~/re-frida"


def _run(pi, desc, cmd, timeout=120, check=True):
    print(f"[i] {desc} ...", flush=True)
    code, out = pi.exec(cmd, timeout=timeout, in_workdir=False)
    if check and code != 0:
        tail = "\n".join(out.strip().splitlines()[-15:]) or "(нет вывода)"
        sys.exit(f"[!] шаг '{desc}' упал (код {code}):\n{tail}")
    return code, out


def _final(frida, version):
    print(f"\n[+] frida установлена: {version}")
    print(f"    CLI на Pi: {frida}")
    print(f"    Хукание требует ptrace -> под sudo, напр.:")
    print(f"      sudo {frida} -f ./sample <clip> -l hook.js")
    print(f"    Атакующий зовёт её через pi_exec; хук-скрипт кладёт через pi_push.")
    print(f"    NB: frida усиливает атаку -> прогоны с ней и без НЕсопоставимы "
          f"(зафиксируй как новую точку отсчёта). Чтобы атакующий её реально "
          f"использовал, добавь упоминание в промпт/TOOLS.")


def main():
    ap = argparse.ArgumentParser(description="Установка frida на Pi (с хоста, по SSH)")
    ap.add_argument("--frida-tools-version", default=None,
                    help=f"версия frida-tools (по умолчанию серия '{DEFAULT_SPEC}')")
    ap.add_argument("--venv", default=DEFAULT_VENV,
                    help=f"путь venv на Pi (по умолчанию {DEFAULT_VENV})")
    ap.add_argument("--force", action="store_true",
                    help="переустановить, даже если frida уже стоит")
    opts = ap.parse_args()

    spec = ("frida-tools==" + opts.frida_tools_version
            if opts.frida_tools_version else DEFAULT_SPEC)
    venv = opts.venv
    frida = f"{venv}/bin/frida"
    pip = f"{venv}/bin/pip"

    from dotenv import load_dotenv
    load_dotenv(HERE / ".env")
    pi = PiDevice.from_env("frida-install")
    if pi is None:
        sys.exit("[!] RE_PI_HOST не задан -- нужен доступ к Pi (см. .env RE_PI_*).")
    pi.connect()

    try:
        _, arch = pi.exec("uname -m", timeout=15, in_workdir=False)
        arch = arch.strip()
        print(f"[i] Pi arch: {arch}")
        if arch not in ("aarch64", "arm64", "armv7l"):
            print(f"[!] предупреждение: непривычная арх '{arch}' -- готовых колёс frida "
                  f"может не быть, pip полезет собирать из исходников.")

        # Уже стоит? (frida --version в отсутствие venv вернёт ненулевой код.)
        code, ver = pi.exec(f"{frida} --version", timeout=30, in_workdir=False)
        if code == 0 and not opts.force:
            print(f"[i] frida уже установлена: {ver.strip()} (в {venv}). "
                  f"Пропускаю. --force чтобы переустановить.")
            _final(frida, ver.strip())
            return 0

        code, _ = pi.exec("python3 -m venv --help", timeout=20, in_workdir=False)
        if code != 0:
            sys.exit("[!] на Pi нет модуля venv. Поставь: sudo apt install -y "
                     "python3-venv -- и запусти скрипт снова.")

        _run(pi, f"создаю venv {venv}", f"python3 -m venv {venv}", timeout=180)
        # Свежий pip ОБЯЗАТЕЛЕН: старый не понимает manylinux2014 -> не найдёт
        # aarch64-колесо frida и полезет собирать из исходников (упадёт).
        _run(pi, "обновляю pip", f"{pip} install --upgrade pip", timeout=300)
        _run(pi, f"ставлю {spec}", f"{pip} install '{spec}'", timeout=900)

        _, ver = _run(pi, "проверяю frida", f"{frida} --version", timeout=60)
        _final(frida, ver.strip())
    finally:
        pi.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\n[прервано пользователем]")
