````markdown
# Shai-Hulud 2.0 Detection Tools

Комплексный инструментарий для обнаружения индикаторов компрометации (IOC) атаки Shai-Hulud 2.0 - самореплицирующегося червя, атакующего npm экосистему через supply chain.

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![No Dependencies](https://img.shields.io/badge/dependencies-none-green.svg)](https://github.com/Krakazybik/shai-hulud-2.0-detection)

## � О атаке

**Shai-Hulud 2.0** - это самореплицирующийся червь, который:

- 🦠 Компрометирует npm пакеты через preinstall/postinstall скрипты
- 🔑 Крадёт credentials (GitHub, NPM, AWS, GCP, Azure, Datadog)
- 🌐 Эксфильтрует данные через публичные GitHub репозитории с описанием "Sha1-Hulud: The Second Coming"
- 🔄 Автоматически распространяется через npm publish
- 💣 Имеет деструктивную функцию удаления домашней директории при неудачной эксфильтрации
- 🤖 Регистрирует машину как GitHub self-hosted runner (SHA1HULUD)
- 🕵️ Использует TruffleHog для автоматического поиска секретов
- ⏱️ Детектирует CI окружение для синхронного/асинхронного выполнения

### Масштаб атаки

- **25,000+** скомпрометированных репозиториев
- **795+** заражённых npm пакетов (по данным Datadog IOCs)
- **132+ миллиона** загрузок в месяц у скомпрометированных пакетов
- Затронуты популярные пакеты от Zapier, PostHog, Postman, ENS Domains, AsyncAPI, Browserbase

---

## ⚡ Быстрое развёртывание

**Один скрипт - скопировать и вставить для сканирования текущей директории:**

```bash
git clone https://github.com/Krakazybik/shai-hulud-2.0-detection.git /tmp/shai-hulud-scanner && \
python3 /tmp/shai-hulud-scanner/shai_hulud_scanner.py . --update-iocs && \
rm -rf /tmp/shai-hulud-scanner
```

**С сохранением JSON отчёта:**

```bash
git clone https://github.com/Krakazybik/shai-hulud-2.0-detection.git /tmp/shai-hulud-scanner && \
python3 /tmp/shai-hulud-scanner/shai_hulud_scanner.py . \
  --update-iocs \
  --json-report shai-hulud-report.json && \
echo "📄 Отчёт сохранён в shai-hulud-report.json" && \
rm -rf /tmp/shai-hulud-scanner
```

**Рекурсивное сканирование всех проектов в директории:**

```bash
git clone https://github.com/Krakazybik/shai-hulud-2.0-detection.git /tmp/shai-hulud-scanner && \
python3 /tmp/shai-hulud-scanner/shai_hulud_scanner.py ~/projects \
  --recursive \
  --update-iocs \
  --json-report scan-results.json && \
rm -rf /tmp/shai-hulud-scanner
```

**Постоянная установка:**

```bash
git clone https://github.com/Krakazybik/shai-hulud-2.0-detection.git && \
cd shai-hulud-2.0-detection && \
./install.sh && \
python3 shai_hulud_scanner.py .
```

> **💡 Требования:** Только Python 3.7+ - никаких дополнительных зависимостей!  
> **🔒 Безопасно:** Сканер использует только встроенные библиотеки Python

---

## 🛠️ Инструменты

### 🔴 Основной сканер: `shai_hulud_scanner.py`

**Комплексный сканер с полным функционалом** - использует ТОЛЬКО встроенные библиотеки Python 3.7+

#### ✨ Возможности

**📦 Проверка зависимостей:**
- ✅ **795+ скомпрометированных пакетов** из [Datadog IOCs](https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0)
- ✅ Автоматическое обновление базы IOCs из GitHub
- ✅ Поддержка `package.json`
- ✅ Поддержка `package-lock.json` (npm v1/v2/v3)
- ✅ Поддержка `yarn.lock`
- ✅ Поддержка `pnpm-lock.yaml` (встроенный парсер, без зависимостей)
- ✅ Обнаружение транзитивных зависимостей

**🔍 Глубокое сканирование кода (16 паттернов):**
- 🔴 Кража credentials (Git, NPM, AWS, GCP, Azure, Datadog)
- 🔴 Использование TruffleHog для поиска секретов
- 🔴 GitHub API эксфильтрация
- 🔴 Instance Metadata Service доступ
- 🔴 Создание IOC файлов (`cloud.json`, `truffleSecrets.json`, etc.)
- 🔴 Деструктивное поведение (удаление домашней директории)
- 🔴 Регистрация GitHub self-hosted runners
- 🟠 Double base64 encoding
- 🟡 Environment variable scraping
- 🟡 CI detection patterns

**⚙️ GitHub Actions Workflows:**
- 🔴 Обнаружение `discussion.yaml` (command injection backdoor)
- 🔴 Поиск `formatter_*.yml` (secrets exfiltration)
- 🔴 Self-hosted runner workflows
- 🔴 Индикаторы Shai-Hulud в workflows

**📊 Отчётность:**
- 📈 Красивый консольный вывод с цветовой индикацией
- 📄 JSON отчёты для автоматизации
- 🎯 Группировка по severity (CRITICAL, HIGH, WARNING)
- 📋 Детальная информация о каждой находке
- 💡 Автоматические рекомендации по устранению

#### 🚀 Использование

```bash
# Установка
./install.sh

# Сканирование одного проекта
python3 shai_hulud_scanner.py ./my-project

# Рекурсивное сканирование
python3 shai_hulud_scanner.py ~/projects --recursive

# Быстрое сканирование (только зависимости)
python3 shai_hulud_scanner.py . --quick

# С обновлением IOCs и JSON отчётом
python3 shai_hulud_scanner.py . --update-iocs --json-report report.json

# Справка
python3 shai_hulud_scanner.py --help
```

#### 📋 Требования

- **Python 3.7+** (только встроенные библиотеки!)
- Никаких внешних зависимостей
- Работает на Linux, macOS, Windows

---

### 2. Semgrep Rules (`shai-hulud-2.0-detection.yaml`)

Набор правил для статического анализа кода на предмет индикаторов Shai-Hulud 2.0. Дополняет основной сканер.

#### Установка Semgrep

```bash
# Через pip
pip install semgrep

# Через Homebrew (macOS)
brew install semgrep

# Через npm
npm install -g @semgrep/cli
```

#### Использование

```bash
# Сканирование текущей директории
semgrep --config shai-hulud-2.0-detection.yaml .

# Сканирование конкретного проекта
semgrep --config shai-hulud-2.0-detection.yaml /path/to/project

# Сканирование с выводом в JSON
semgrep --config shai-hulud-2.0-detection.yaml --json -o report.json .

# Сканирование только критичных проблем
semgrep --config shai-hulud-2.0-detection.yaml --severity ERROR .
```

#### Что обнаруживает

- ✅ Malicious файлы: `setup_bun.js`, `bun_environment.js`
- ✅ Подозрительные preinstall/postinstall скрипты
- ✅ Кражу credentials (GitHub, NPM, AWS, GCP, Azure)
- ✅ Использование TruffleHog для поиска секретов
- ✅ Эксфильтрацию через GitHub API
- ✅ Репозитории с описанием "Sha1-Hulud: The Second Coming"
- ✅ GitHub self-hosted runner "SHA1HULUD"
- ✅ Malicious workflow файлы
- ✅ Доступ к Instance Metadata Service
- ✅ Деструктивное поведение (удаление home directory)
- ✅ Double base64 encoding
- ✅ Автоматическую установку Bun runtime
- ✅ Автоматический npm publish

---

### 3. Legacy Scanner (v2)

Предыдущая версия для обратной совместимости:

**`shai_hulud_scanner_v2.py`:**
- Поддержка lock файлов (npm, yarn, pnpm)
- Обнаружение транзитивных зависимостей
- Улучшенная отчётность

**⚠️ Рекомендация:** Используйте `shai_hulud_scanner.py` (основной сканер) для максимальной защиты.

---

## 🗂️ База IOCs

Сканнер использует актуальную базу индикаторов компрометации из нескольких источников:

- **Datadog Security Labs** - 795+ пакетов
- Wiz Research
- SafeDep
- Helixguard, Koi, ReversingLabs
- SocketDev, StepSecurity

### Примеры скомпрометированных пакетов

| Пакет | Версии | Источники |
|-------|--------|-----------|
| `zapier-platform-core` | 18.0.2, 18.0.3, 18.0.4 | Datadog, Wiz, ReversingLabs |
| `posthog-node` | 4.18.1, 5.11.3, 5.13.3 | Datadog, HelixGuard, Koi |
| `@ensdomains/ensjs` | 4.0.3 | Datadog, ReversingLabs |
| `@postman/postman-mcp-cli` | 1.0.3, 1.0.4, 1.0.5 | Datadog, Wiz, StepSecurity |
| `@browserbasehq/stagehand` | 3.0.4 | Datadog, SocketDev |
| `@asyncapi/*` | 30+ пакетов | Множественные источники |

**Полный список:** `consolidated_iocs.csv` (795+ пакетов)

---

## 📊 CI/CD Integration

### GitHub Actions

```yaml
name: Shai-Hulud 2.0 Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Clone Shai-Hulud Scanner
        run: |
          git clone https://github.com/Krakazybik/shai-hulud-2.0-detection.git /tmp/scanner
      
      - name: Run Shai-Hulud Scanner
        run: |
          python3 /tmp/scanner/shai_hulud_scanner.py . \
            --update-iocs \
            --json-report scan-report.json
      
      - name: Upload scan report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: shai-hulud-scan-report
          path: scan-report.json
      
      # Опционально: Semgrep для дополнительной проверки
      - name: Install Semgrep
        run: pip install semgrep
      
      - name: Run Semgrep scan
        run: |
          semgrep --config /tmp/scanner/shai-hulud-2.0-detection.yaml \
                  --severity ERROR \
                  --error \
                  .
```

### GitLab CI

```yaml
shai-hulud-scan:
  image: python:3.11
  script:
    # Клонирование сканера
    - git clone https://github.com/Krakazybik/shai-hulud-2.0-detection.git /tmp/scanner
    
    # Сканирование Python сканером
    - python3 /tmp/scanner/shai_hulud_scanner.py . --update-iocs --json-report report.json
    
    # Опционально: Semgrep
    - pip install semgrep
    - semgrep --config /tmp/scanner/shai-hulud-2.0-detection.yaml --error .
  artifacts:
    reports:
      sast: report.json
    paths:
      - report.json
    when: always
  only:
    - merge_requests
    - main

# Быстрое сканирование для feature веток
quick-scan:
  image: python:3.11
  script:
    - git clone https://github.com/Krakazybik/shai-hulud-2.0-detection.git /tmp/scanner
    - python3 /tmp/scanner/shai_hulud_scanner.py . --quick
  only:
    - branches
  except:
    - main
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Clone Scanner') {
            steps {
                sh 'git clone https://github.com/Krakazybik/shai-hulud-2.0-detection.git /tmp/scanner'
            }
        }
        
        stage('Shai-Hulud Scan') {
            steps {
                sh '''
                    python3 /tmp/scanner/shai_hulud_scanner.py . \
                        --update-iocs \
                        --json-report scan-report.json
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'scan-report.json', allowEmptyArchive: true
        }
        cleanup {
            sh 'rm -rf /tmp/scanner'
        }
    }
}
```

### CircleCI

```yaml
version: 2.1

jobs:
  shai-hulud-scan:
    docker:
      - image: python:3.11
    steps:
      - checkout
      
      - run:
          name: Clone Scanner
          command: git clone https://github.com/Krakazybik/shai-hulud-2.0-detection.git /tmp/scanner
      
      - run:
          name: Run Shai-Hulud Scanner
          command: |
            python3 /tmp/scanner/shai_hulud_scanner.py . \
              --update-iocs \
              --json-report scan-report.json
      
      - store_artifacts:
          path: scan-report.json
          destination: shai-hulud-report

workflows:
  version: 2
  security-scan:
    jobs:
      - shai-hulud-scan
```

---

## 🧪 Тестирование

Репозиторий включает набор тестовых примеров для проверки работы сканера:

```bash
# Тест на чистом проекте (должен пройти)
python3 shai_hulud_scanner.py test-samples/clean-test/

# Тест на вредоносных файлах (должен обнаружить угрозы)
python3 shai_hulud_scanner.py test-samples/malicious/

# Тест на скомпрометированных пакетах
python3 shai_hulud_scanner.py test-samples/malicious/test-package-compromised-zapier/

# Рекурсивное тестирование всех примеров
python3 shai_hulud_scanner.py test-samples/ --recursive
```

### Структура тестов

```
test-samples/
├── clean/              # Чистые примеры (легитимный код)
├── clean-test/         # Тестовый чистый проект
├── malicious/          # Вредоносные примеры
│   ├── credential-theft.js
│   ├── environment-scraping.js
│   ├── ioc-files.js
│   ├── github-exfiltration.js
│   └── test-package-*/  # Скомпрометированные проекты
└── workflows/          # Примеры вредоносных workflows
```

## 🔗 Ссылки и источники

### Исследования атаки
- [Datadog Security Labs - Полный анализ](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Wiz Research - IOCs и детали](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [SafeDep - Incident Report](https://safedep.io/shai-hulud-second-coming-supply-chain-attack/)
- [Aikido Security - Анализ Zapier/ENS](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)
- [Palo Alto Unit 42 - Supply Chain Attack](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)

### Базы IOCs
- [Datadog IOCs (GitHub)](https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0) - **Основная база**
- [Wiz IOCs GitHub](https://github.com/wiz-sec-public/wiz-research-iocs)
- [SafeDep Migration Response](https://github.com/safedep/shai-hulud-migration-response)

### Инструменты мониторинга
- [Socket Security](https://socket.dev/blog) - Continuous monitoring
- [Datadog Supply Chain Security](https://www.datadoghq.com/product/software-delivery/supply-chain-security/)
- [GitHub Dependabot](https://docs.github.com/en/code-security/dependabot)
- [Snyk](https://snyk.io/)

---

## 🤝 Участие в проекте

Сообщения об ошибках, предложения улучшений и pull requests приветствуются!

1. Fork репозитория
2. Создайте feature ветку (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

### Обновление базы IOCs

Если вы обнаружили новые скомпрометированные пакеты:
1. Добавьте их в `consolidated_iocs.csv`
2. Обновите тесты в `test-samples/`
3. Отправьте PR с описанием источника информации

## ⚠️ Disclaimer

Эти инструменты предоставляются "как есть" для помощи в обнаружении индикаторов Shai-Hulud 2.0. Они не гарантируют 100% обнаружение всех вариантов атаки. 

**Используйте в сочетании с:**
- Code review процессами
- Dependency scanning tools
- Runtime monitoring
- Security awareness training
- MFA на всех аккаунтах
- Principle of least privilege

## 📄 Лицензия

MIT License - свободно используйте и модифицируйте для защиты вашей инфраструктуры.

См. [LICENSE](LICENSE) для подробностей.

---

## 📈 Статистика

- **795+** скомпрометированных пакетов в базе IOCs
- **16** паттернов вредоносного кода
- **0** внешних зависимостей
- **100%** покрытие тестовых примеров

---

**Разработано:** 2025  
**Статус:** Активно поддерживается  
**Последнее обновление:** November 26, 2025  
**Статус угрозы:** 🔴 АКТИВНА - новые скомпрометированные пакеты появляются ежедневно

**⚡ Защитите свою инфраструктуру прямо сейчас!**

````

### Очистка

```bash
# Удалите node_modules и lock файлы
rm -rf node_modules package-lock.json yarn.lock

# Установите чистые версии
npm install

# Проверьте package.json на изменения
git diff package.json
```

### Долгосрочные меры

1. **Включите MFA** на GitHub и NPM (WebAuthn/FIDO2)
2. **Используйте npm provenance** для верификации пакетов
3. **Ограничьте lifecycle скрипты** в CI/CD:
   ```bash
   npm install --ignore-scripts
   ```
4. **Мониторинг dependencies** с помощью:
   - GitHub Dependabot
   - Snyk
   - Socket Security
   - Datadog Supply Chain Security Firewall

---

3. Отправьте PR с описанием источника информации

---

- Principle of least privilege

---

## 📄 Лицензия

MIT License - свободно используйте и модифицируйте для защиты вашей инфраструктуры.

---

**Последнее обновление:** November 2025  
**Статус угрозы:** АКТИВНА - новые скомпрометированные пакеты появляются регулярно
