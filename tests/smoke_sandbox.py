"""Проверка docker-обвязки agent.py без обращения к моделям.

Запуск (из корня проекта):
    python tests\\smoke_sandbox.py

Проверяет то, что ломается тише всего: PATH внутри контейнера, монтирование
тома, отсутствие сети, срабатывание таймаута, кодировки, работу обёрток.
Ключей от API не требует, денег не тратит.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent import Sandbox, truncate  # noqa: E402

WORK = Path(__file__).resolve().parent.parent / "runs" / "_smoke"


def main():
    sb = Sandbox("re-workbench:latest", WORK, "re-smoke-test", "smoke")
    sb.start()
    print("контейнер запущен")
    checks = []
    try:
        code, out = sb.run("echo привет; pwd")
        checks.append(("команда и кириллица", code == 0 and "привет" in out, out.split("\n")[0]))

        code, out = sb.run("ls -la /work | head -3")
        checks.append(("том смонтирован", code == 0 and "total" in out, ""))

        code, out = sb.run("curl -s -m 5 https://example.com || echo NETWORK_BLOCKED")
        checks.append(("сети нет", "NETWORK_BLOCKED" in out, ""))

        t = time.time()
        code, out = sb.run("sleep 30", timeout=3)
        dt = time.time() - t
        checks.append(("таймаут срабатывает", dt < 12 and "таймаут" in out, f"{dt:.1f} c"))

        sb.write_file("/work/hello.py", "print('ok из файла')\n")
        code, out = sb.run("python3 /work/hello.py")
        checks.append(("write_file и запуск", "ok из файла" in out, ""))

        tools = sb.read_text("/opt/re/TOOLS.md")
        checks.append(("TOOLS.md читается", len(tools) > 500, f"{len(tools)} симв."))

        # PATH: обёртки лежат в /opt/re/bin, который затирается login-шеллом.
        code, out = sb.run("rpi-run /opt/rpi-root/arm64/usr/bin/uname -m")
        checks.append(("ARM-эмуляция через обёртку", "aarch64" in out, out.strip()[:40]))

        code, out = sb.run("re-note 'пробная находка' --conf 0.4 && tail -1 /work/findings.jsonl")
        checks.append(("re-note пишет findings", "пробная находка" in out, ""))

        code, out = sb.run("ghidra-funcs 2>&1 | head -2")
        checks.append(("ghidra-* отвечают внятно", "ghidra-analyze" in out or "Дамп" in out, ""))

        big = truncate("x" * 100_000)
        checks.append(("обрезка вывода", "вырезано" in big and len(big) < 25_000, f"{len(big)} симв."))
    finally:
        sb.stop()

    print()
    bad = 0
    for name, ok, detail in checks:
        print(("  OK   " if ok else "  FAIL ") + f"{name:<28} {detail}")
        bad += 0 if ok else 1
    print(f"\nпровалов: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
