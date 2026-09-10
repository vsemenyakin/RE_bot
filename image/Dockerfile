# syntax=docker/dockerfile:1.7
#
# re-workbench — песочница для реверс-инжиниринга бинарей Raspberry Pi OS (ARM).
#
# Хост x86_64, цели ARM. Статика (Ghidra/radare2) считается нативно и быстро,
# динамика — под qemu-user с ARM-корнями, вкомпилированными в образ.
#
# Сборка НЕ требует binfmt/QEMU на хосте: ARM-корни собираются скачиванием
# .deb для чужой архитектуры и распаковкой их через dpkg-deb, то есть ни один
# ARM-бинарь при сборке не запускается. Эмуляция нужна только в рантайме и
# вызывается явно (qemu-aarch64-static), мимо binfmt.
#
#   docker build -t re-workbench:latest image
#
# Под какой выпуск Debian собираем ARM-корни. Raspberry Pi OS основана на Debian:
#   trixie   — Pi OS 2025+ (Debian 13)
#   bookworm — Pi OS 2023-2024 (Debian 12)
ARG RPI_SUITE=trixie
ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_BUILD=20260817

FROM debian:${RPI_SUITE}-slim AS workbench
ARG GHIDRA_VERSION
ARG GHIDRA_BUILD
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

# Обязательный минимум: без него образ бессмысленен, падение сборки здесь — сигнал.
RUN apt-get update && apt-get install -y --no-install-recommends \
      openjdk-21-jdk-headless \
      python3 python3-venv python3-dev \
      build-essential pkg-config \
      curl ca-certificates unzip xz-utils \
      file binutils \
      binutils-aarch64-linux-gnu binutils-arm-linux-gnueabihf \
      gdb-multiarch \
      qemu-user-static \
      less jq git ripgrep vim-common bsdextrautils procps \
      openssh-client sshpass \
 && rm -rf /var/lib/apt/lists/*

# Желательное: отсутствие пакета в конкретном выпуске не должно ронять сборку.
RUN apt-get update \
 && for p in radare2 yara binwalk squashfs-tools cpio dpkg-dev upx-ucl \
             strace ltrace checksec fdupes patchelf cmake \
             gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf; do \
      apt-get install -y --no-install-recommends "$p" || echo "SKIP apt: $p" >> /opt/re-build-skipped.txt; \
    done \
 && rm -rf /var/lib/apt/lists/*

# --- ARM-корни для qemu-user ----------------------------------------------
# qemu-user ищет по -L динамический загрузчик и .so целевой архитектуры.
# Берём их из Debian того же выпуска: скачиваем .deb и распаковываем.
# Ничего ARM-ного при этом не исполняется, поэтому binfmt на хосте не нужен.
RUN set -eux; \
    dpkg --add-architecture arm64; \
    dpkg --add-architecture armhf; \
    apt-get update; \
    for arch in arm64 armhf; do \
      root="/opt/rpi-root/$arch"; \
      mkdir -p "$root" "/tmp/debs/$arch"; \
      cd "/tmp/debs/$arch"; \
      for p in libc6 libgcc-s1 libstdc++6 zlib1g libcrypt1 \
               libssl3t64 libssl3 \
               libcurl4t64 libcurl4 libsqlite3-0 libffi8 libexpat1 \
               libpcre2-8-0 libuuid1 libbz2-1.0 liblzma5 libzstd1 \
               libtinfo6 libncursesw6 libreadline8t64 libreadline8 \
               libudev1 libsystemd0 libcap2 libgpg-error0 libgcrypt20 \
               libselinux1 libacl1 libattr1 coreutils; do \
        apt-get download "$p:$arch" 2>/dev/null || echo "SKIP deb: $p:$arch" >> /opt/re-build-skipped.txt; \
      done; \
      n=0; \
      for d in *.deb; do \
        [ -e "$d" ] || continue; \
        dpkg-deb -x "$d" "$root"; n=$((n+1)); \
      done; \
      echo "rootfs $arch: распаковано пакетов: $n"; \
      test "$n" -gt 0; \
      for d in bin sbin lib lib32 lib64 libx32; do \
        if [ -d "$root/usr/$d" ] && [ ! -e "$root/$d" ]; then ln -s "usr/$d" "$root/$d"; fi; \
      done; \
      mkdir -p "$root/proc" "$root/sys" "$root/tmp" "$root/dev" "$root/etc"; \
    done; \
    cd /; rm -rf /tmp/debs /var/lib/apt/lists/*; \
    test -e /opt/rpi-root/arm64/lib/ld-linux-aarch64.so.1; \
    test -e /opt/rpi-root/armhf/lib/ld-linux-armhf.so.3

# --- Ghidra ---------------------------------------------------------------
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
RUN set -eux; \
    url="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip"; \
    curl -fsSL -o /tmp/ghidra.zip "$url"; \
    unzip -q /tmp/ghidra.zip -d /opt; \
    mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" "$GHIDRA_INSTALL_DIR"; \
    rm /tmp/ghidra.zip; \
    test -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"

# --- Python-инструменты ----------------------------------------------------
# Отдельный venv: в Debian 12+ системный pip заблокирован (PEP 668).
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv "$VIRTUAL_ENV" && "$VIRTUAL_ENV/bin/pip" install --no-cache-dir -U pip wheel
ENV PATH="/opt/venv/bin:/opt/re/bin:${GHIDRA_INSTALL_DIR}/support:${PATH}"

# Ядро: разбор ELF, дизасм, мост в Ghidra. Должно встать обязательно.
RUN pip install --no-cache-dir pyelftools capstone lief r2pipe \
 && pip install --no-cache-dir --no-index \
      -f "${GHIDRA_INSTALL_DIR}/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra

# Тяжёлое и капризное к версии Python — ставим по одному, без права уронить сборку.
RUN for p in angr unicorn qiling flare-capa pwntools ropper frida-tools; do \
      pip install --no-cache-dir "$p" || echo "SKIP pip: $p" >> /opt/re-build-skipped.txt; \
    done

# --- radare2 ---------------------------------------------------------------
# Из Debian trixie пакет удалён (apt-шаг выше это фиксирует), ставим .deb апстрима.
ARG R2_VERSION=6.2.2
RUN set -eux; \
    url="https://github.com/radareorg/radare2/releases/download/${R2_VERSION}/radare2_${R2_VERSION}_amd64.deb"; \
    if curl -fsSL -o /tmp/r2.deb "$url"; then \
      apt-get update; \
      apt-get install -y --no-install-recommends /tmp/r2.deb; \
      rm -rf /var/lib/apt/lists/* /tmp/r2.deb; \
      r2 -qv; \
      printf 'e scr.color=0\ne scr.interactive=false\n' > /root/.radare2rc; \
      sed -i '/SKIP apt: radare2/d' /opt/re-build-skipped.txt 2>/dev/null || true; \
    else \
      echo "SKIP r2: не скачался ${R2_VERSION}" >> /opt/re-build-skipped.txt; \
    fi

# --- Node.js + claude CLI --------------------------------------------------
# Нужны для атаки через ПОДПИСКУ Claude Code: claude -p бежит прямо в этом
# контейнере, среди RE-инструментов, авторизуясь смонтированным OAuth-токеном.
# Node 20 в trixie удовлетворяет требованию claude (>=18). Только для subscription-
# ветки; litellm-модели claude не используют. Необязательное -- сборку не роняет.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nodejs npm \
 && npm install -g @anthropic-ai/claude-code 2>/dev/null \
 && node --version && claude --version \
 && rm -rf /var/lib/apt/lists/* /root/.npm \
 || echo "SKIP node/claude: не установились" >> /opt/re-build-skipped.txt

# Non-root пользователь для claude: Claude Code отказывается работать в
# автономном режиме (--dangerously-skip-permissions) под root -- защита от
# случайного сноса системы. subscription-ветка запускает claude от него
# (--user reuser). litellm-ветка (docker exec от root) его не касается.
# Инструменты в /opt/re, /opt/venv, /opt/ghidra читаемы/исполнимы всеми.
RUN useradd -m -u 1000 -s /bin/bash reuser

# --- Наша обвязка ----------------------------------------------------------
COPY bin/     /opt/re/bin/
COPY lib/     /opt/re/lib/
COPY scripts/ /opt/re/scripts/
COPY TOOLS.md /opt/re/TOOLS.md
RUN chmod +x /opt/re/bin/* /opt/re/scripts/*.sh && ln -sf /opt/re/TOOLS.md /TOOLS.md \
 && printf 'PATH="/opt/venv/bin:/opt/re/bin:%s/support:$PATH"\n' "$GHIDRA_INSTALL_DIR" \
      > /etc/profile.d/re-workbench.sh \
 && echo 'export PATH' >> /etc/profile.d/re-workbench.sh

ENV RE_ROOT=/opt/re \
    RE_FINDINGS=/work/findings.jsonl \
    RE_AGENT=unknown
WORKDIR /work
CMD ["/bin/bash"]
