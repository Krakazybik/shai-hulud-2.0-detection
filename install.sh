#!/bin/bash

# Установщик Shai-Hulud 2.0 Scanner
# Использует только встроенные библиотеки Python 3

set -e

echo "========================================"
echo "🛡️  Shai-Hulud 2.0 Scanner - Установка"
echo "========================================"
echo ""

# Проверка Python 3
echo "🔍 Проверка Python 3..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 не найден. Установите Python 3.7 или выше."
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✅ Найден Python $PYTHON_VERSION"
echo ""

# Проверка минимальной версии Python (3.7+)
PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 7 ]); then
    echo "❌ Требуется Python 3.7 или выше. Ваша версия: $PYTHON_VERSION"
    exit 1
fi

echo "✅ Версия Python подходит (требуется 3.7+)"
echo ""

# Проверка встроенных модулей
echo "🔍 Проверка встроенных модулей Python..."
python3 << 'EOF'
import sys

required_modules = [
    'json',
    'sys',
    'os',
    're',
    'csv',
    'urllib.request',
    'pathlib',
    'datetime',
    'argparse'
]

missing = []
for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        missing.append(module)

if missing:
    print(f"❌ Отсутствуют модули: {', '.join(missing)}")
    sys.exit(1)

print("✅ Все необходимые модули доступны")
EOF

echo ""

# Установка прав на выполнение
echo "🔧 Установка прав на выполнение..."
chmod +x shai_hulud_scanner_final.py
echo "✅ Права установлены"
echo ""

# Проверка наличия IOCs файла
echo "🔍 Проверка базы IOCs..."
if [ -f "consolidated_iocs.csv" ]; then
    IOC_COUNT=$(wc -l < consolidated_iocs.csv)
    echo "✅ Найден файл IOCs ($IOC_COUNT строк)"
else
    echo "⚠️  Файл consolidated_iocs.csv не найден"
    echo "   Сканнер будет использовать fallback базу"
fi
echo ""

# Тестовый запуск
echo "🧪 Тестовый запуск..."
if python3 shai_hulud_scanner_final.py --version > /dev/null 2>&1; then
    VERSION=$(python3 shai_hulud_scanner_final.py --version 2>&1)
    echo "✅ Сканнер работает: $VERSION"
else
    echo "❌ Ошибка запуска сканнера"
    exit 1
fi
echo ""

# Создание символической ссылки (опционально)
echo "📦 Хотите создать глобальную команду 'shai-hulud-scan'? [y/N]"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    INSTALL_DIR="/usr/local/bin"
    SCRIPT_PATH="$(pwd)/shai_hulud_scanner_final.py"
    
    if [ -w "$INSTALL_DIR" ]; then
        ln -sf "$SCRIPT_PATH" "$INSTALL_DIR/shai-hulud-scan"
        echo "✅ Команда 'shai-hulud-scan' установлена"
    else
        echo "⚠️  Требуются права sudo для установки в $INSTALL_DIR"
        echo "   Выполните: sudo ln -sf $SCRIPT_PATH $INSTALL_DIR/shai-hulud-scan"
    fi
fi

echo ""
echo "========================================"
echo "✅ Установка завершена!"
echo "========================================"
echo ""
echo "📖 Использование:"
echo "   python3 shai_hulud_scanner_final.py <путь>"
echo "   python3 shai_hulud_scanner_final.py --help"
echo ""
echo "📚 Примеры:"
echo "   python3 shai_hulud_scanner_final.py ./my-project"
echo "   python3 shai_hulud_scanner_final.py ~/projects --recursive"
echo "   python3 shai_hulud_scanner_final.py . --update-iocs"
echo ""
echo "🔬 Тестирование:"
echo "   python3 shai_hulud_scanner_final.py test-samples/clean-test/"
echo "   python3 shai_hulud_scanner_final.py test-samples/malicious/"
echo ""
echo "📊 Возможности:"
echo "   ✅ Проверка 795+ скомпрометированных пакетов"
echo "   ✅ Сканирование JS/TS файлов на вредоносные паттерны"
echo "   ✅ Анализ GitHub Actions workflows"
echo "   ✅ Поддержка npm, yarn, pnpm lock файлов"
echo "   ✅ Рекурсивное сканирование проектов"
echo "   ✅ JSON отчёты"
echo ""
echo "⚠️  Примечание: Сканнер использует ТОЛЬКО встроенные библиотеки Python"
echo "              Никаких дополнительных зависимостей не требуется!"
echo ""
