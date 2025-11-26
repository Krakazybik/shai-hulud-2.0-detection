# Shai-Hulud 2.0 Detection Tools

Инструменты для обнаружения индикаторов компрометации (IOC) атаки Shai-Hulud 2.0 - агрессивной supply chain атаки на npm экосистему.

## 📋 О атаке

**Shai-Hulud 2.0** - это самореплицирующийся червь, который:

- 🦠 Компрометирует npm пакеты через preinstall скрипты
- 🔑 Крадёт credentials (GitHub, NPM, AWS, GCP, Azure, Datadog)
- 🌐 Эксфильтрует данные через публичные GitHub репозитории с описанием "Sha1-Hulud: The Second Coming"
- 🔄 Автоматически распространяется через npm publish
- 💣 Имеет деструктивную функцию удаления домашней директории при неудачной эксфильтрации
- 🤖 Регистрирует машину как GitHub self-hosted runner (SHA1HULUD)

### Масштаб атаки

- **25,000+** скомпрометированных репозиториев
- **800+** заражённых npm пакетов
- **132 миллиона** загрузок в месяц у скомпрометированных пакетов
- Затронуты популярные пакеты от Zapier, PostHog, Postman, ENS Domains, AsyncAPI

## 🛠️ Инструменты

### 1. Semgrep Rules (`shai-hulud-2.0-detection.yaml`)

Набор правил для статического анализа кода на предмет индикаторов Shai-Hulud 2.0.

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

### 2. Package Scanner (`shai_hulud_scanner.py`)

Python скрипт для проверки `package.json` на наличие известных скомпрометированных пакетов.

#### Требования

```bash
python3 -m pip install --upgrade pip
# Скрипт использует только стандартную библиотеку Python
```

#### Использование

```bash
# Сканирование одного package.json
python3 shai_hulud_scanner.py ./package.json

# Рекурсивное сканирование директории
python3 shai_hulud_scanner.py ./projects

# Через shebang (если сделан chmod +x)
./shai_hulud_scanner.py ./package.json
```

#### Что обнаруживает

- ✅ Известные скомпрометированные пакеты и версии
- ✅ Malicious индикаторы в скриптах
- ✅ Подозрительные lifecycle скрипты (preinstall, postinstall)
- ✅ Подозрительные паттерны (curl, wget, bun)
- ✅ Ссылки на malicious файлы
- ✅ Подозрительные репозитории

#### Известные скомпрометированные пакеты

- `zapier-platform-core@0.15.x`
- `zapier-platform-cli@18.0.x`
- `zapier-sdk@1.0.0`
- `@asyncapi/specs@7.6.4`
- `posthog-node@4.2.1`
- `@postman/postman-mcp-cli@0.1.0`
- `@ensdomains/ensjs@4.1.0`
- И другие...

## 🚨 Что делать при обнаружении

### Немедленные действия

1. **Изолируйте систему**
   - Отключите от сети если возможно
   - Остановите CI/CD пайплайны

2. **Ротация credentials**
   ```bash
   # GitHub tokens
   # Перейдите: Settings → Developer settings → Personal access tokens → Revoke all
   
   # NPM tokens
   npm token revoke --all
   
   # AWS credentials
   aws iam delete-access-key --access-key-id <KEY_ID>
   
   # GCP credentials
   gcloud auth revoke --all
   ```

3. **Проверьте GitHub на созданные репозитории**
   ```bash
   # Поиск в GitHub
   # https://github.com/search?q=Sha1-Hulud%3A+The+Second+Coming&type=repositories
   ```

4. **Проверьте GitHub Actions runners**
   ```bash
   # Settings → Actions → Runners
   # Найдите и удалите runner с именем "SHA1HULUD"
   ```

5. **Проверьте workflows**
   ```bash
   # Проверьте .github/workflows/discussion.yaml
   find . -name "discussion.yaml" -path "*/.github/workflows/*"
   ```

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

## 📊 CI/CD Integration

### GitHub Actions

```yaml
name: Shai-Hulud Detection
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Semgrep
        run: pip install semgrep
      
      - name: Run Semgrep scan
        run: |
          semgrep --config shai-hulud-2.0-detection.yaml \
                  --severity ERROR \
                  --error \
                  .
      
      - name: Scan package.json
        run: python3 shai_hulud_scanner.py .
```

### GitLab CI

```yaml
shai-hulud-scan:
  image: python:3.11
  script:
    - pip install semgrep
    - semgrep --config shai-hulud-2.0-detection.yaml --error .
    - python3 shai_hulud_scanner.py .
  only:
    - merge_requests
    - main
```

## 🔗 Ссылки и источники

- [Datadog Security Labs Analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Wiz Research IOCs](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [SafeDep Incident Report](https://safedep.io/shai-hulud-second-coming-supply-chain-attack/)
- [Aikido Security Blog](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)
- [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)

## 📝 Обновление правил

Список скомпрометированных пакетов регулярно обновляется. Следите за:

- [Wiz IOCs GitHub](https://github.com/wiz-sec-public/wiz-research-iocs)
- [SafeDep Migration Response](https://github.com/safedep/shai-hulud-migration-response)
- [Socket Security Blog](https://socket.dev/blog)

## ⚠️ Disclaimer

Эти инструменты предоставляются "как есть" для помощи в обнаружении индикаторов Shai-Hulud 2.0. Они не гарантируют 100% обнаружение всех вариантов атаки. Используйте в сочетании с другими security практиками.

## 📄 Лицензия

MIT License - свободно используйте и модифицируйте для защиты вашей инфраструктуры.

---

**Последнее обновление:** November 2025  
**Статус угрозы:** АКТИВНА - новые скомпрометированные пакеты появляются регулярно
