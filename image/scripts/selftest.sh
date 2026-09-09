#!/bin/bash
# Проверка образа: что установилось, что нет, работает ли эмуляция ARM.
# Запуск: docker run --rm re-workbench:latest bash /opt/re/scripts/selftest.sh
set -uo pipefail

ok=0; bad=0
check() {
    if command -v "$1" >/dev/null 2>&1; then
        printf '  \033[32mOK\033[0m   %-28s %s\n' "$1" "$(command -v "$1")"; ok=$((ok+1))
    else
        printf '  \033[31mMISS\033[0m %-28s\n' "$1"; bad=$((bad+1))
    fi
}
pycheck() {
    if python3 -c "import $1" 2>/dev/null; then
        printf '  \033[32mOK\033[0m   python:%-21s\n' "$1"; ok=$((ok+1))
    else
        printf '  \033[33mMISS\033[0m python:%-21s (необязательный)\n' "$1"; bad=$((bad+1))
    fi
}

echo "== инструменты командной строки =="
for c in java python3 readelf objdump nm strings file \
         aarch64-linux-gnu-objdump arm-linux-gnueabihf-objdump \
         gdb-multiarch qemu-aarch64-static qemu-arm-static \
         r2 yara binwalk upx rg jq; do check "$c"; done

echo
echo "== обвязка =="
for c in ghidra-analyze ghidra-funcs ghidra-decompile ghidra-xrefs rpi-info rpi-run re-note re-help; do
    check "$c"
done

echo
echo "== python-пакеты =="
for m in elftools capstone lief pyghidra r2pipe angr unicorn qiling capa pwnlib; do pycheck "$m"; done

echo
echo "== Ghidra =="
if [ -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]; then
    printf '  \033[32mOK\033[0m   %s\n' "$GHIDRA_INSTALL_DIR"
    java -version 2>&1 | head -1 | sed 's/^/       /'
else
    printf '  \033[31mMISS\033[0m Ghidra не найдена в %s\n' "${GHIDRA_INSTALL_DIR:-?}"; bad=$((bad+1))
fi

echo
echo "== ARM-корни =="
for r in /opt/rpi-root/arm64 /opt/rpi-root/armhf; do
    if [ -e "$r/lib/ld-linux-aarch64.so.1" ] || [ -e "$r/lib/ld-linux-armhf.so.3" ]; then
        printf '  \033[32mOK\033[0m   %-28s %s\n' "$r" "$(du -sh "$r" 2>/dev/null | cut -f1)"
    else
        printf '  \033[31mMISS\033[0m %s (нет динамического загрузчика)\n' "$r"; bad=$((bad+1))
    fi
done

echo
echo "== живой тест эмуляции =="
# Гоняем настоящий ARM-бинарь из корня. Если это не работает, не будет
# работать и rpi-run на анализируемом образце.
for arch in arm64 armhf; do
    probe="/opt/rpi-root/$arch/usr/bin/uname"
    if [ ! -x "$probe" ]; then
        printf '  \033[33mSKIP\033[0m %s: нет пробного бинаря (coreutils:%s не скачался)\n' "$arch" "$arch"
        continue
    fi
    if out=$(rpi-run "$probe" -m 2>/dev/null); then
        printf '  \033[32mOK\033[0m   %-6s запуск под qemu, uname -m -> %s\n' "$arch" "$out"; ok=$((ok+1))
    else
        printf '  \033[31mFAIL\033[0m %-6s ARM-бинарь не запускается\n' "$arch"; bad=$((bad+1))
    fi
    if rpi-run --strace "$probe" -m >/dev/null 2>&1; then
        printf '  \033[32mOK\033[0m   %-6s трассировка системных вызовов\n' "$arch"; ok=$((ok+1))
    else
        printf '  \033[31mFAIL\033[0m %-6s --strace не работает\n' "$arch"; bad=$((bad+1))
    fi
done

echo
[ -f /opt/re-build-skipped.txt ] && { echo "== не установилось при сборке =="; sed 's/^/  /' /opt/re-build-skipped.txt; echo; }
echo "итого: OK=$ok, отсутствует=$bad"
