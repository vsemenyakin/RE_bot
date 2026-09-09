@echo off
REM RE-сессия в один клик. Двойной клик по этому файлу или `run_RE` в консоли.
REM Всю логику ведёт run_RE.py; аргументы атаки -- в RE_args.txt.
cd /d "%~dp0"
python run_RE.py %*
echo.
pause
