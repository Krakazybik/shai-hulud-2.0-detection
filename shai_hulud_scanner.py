#!/usr/bin/env python3
"""
Shai-Hulud 2.0 Scanner
"""

import json
import sys
import os
import re
import csv
import urllib.request
from typing import Dict, List, Set, Tuple, Optional
from pathlib import Path
from datetime import datetime

# URL списка IOCs от Datadog
DATADOG_IOCS_URL = "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv"
LOCAL_IOCS_FILE = Path(__file__).parent / "consolidated_iocs.csv"

# Базовый список (если не удается загрузить из GitHub)
FALLBACK_COMPROMISED_PACKAGES = {
    "zapier-platform-core": ["0.15.0", "0.15.1"],
    "zapier-platform-cli": ["18.0.0", "18.0.1"],
    "zapier-sdk": ["1.0.0"],
    "@asyncapi/specs": ["7.6.4"],
    "@asyncapi/parser": ["3.3.1"],
    "@asyncapi/modelina": ["4.3.0"],
    "posthog-node": ["4.2.1"],
    "posthog-js": ["1.165.0"],
    "@postman/postman-mcp-cli": ["0.1.0"],
    "@ensdomains/ensjs": ["4.1.0"],
    "@browserbasehq/sdk": ["1.5.0"],
}

# Индикаторы компрометации
MALICIOUS_INDICATORS = [
    "setup_bun.js",
    "bun_environment.js",
    "SHA1HULUD",
    "Sha1-Hulud",
    "Shai-Hulud",
]

# Подозрительные скрипты
SUSPICIOUS_SCRIPT_PATTERNS = [
    r"curl.*https?://[^\s]+",
    r"wget.*https?://[^\s]+",
    r"bash.*<<.*EOF",
    r"node.*setup_bun",
    r"bun.*bun_environment",
    r"npm.*publish",
]

# Паттерны для сканирования JS/TS файлов
JS_MALICIOUS_PATTERNS = {
    'credential_theft_git': r'(?:fs\.read(?:File)?Sync\([^)]*[\'"]\.git(?:config|credentials)|\.git(?:config|credentials)[\'"])',
    'credential_theft_npm': r'(?:fs\.read(?:File)?Sync\([^)]*[\'"]\.npmrc|\.npmrc[\'"])',
    'credential_theft_aws': r'(?:fs\.read(?:File)?Sync\([^)]*[\'"]\.aws[/\\]credentials|\.aws[/\\]credentials[\'"])',
    'credential_theft_gcp': r'(?:fs\.read(?:File)?Sync\([^)]*[\'"]\.config[/\\]gcloud|\.config[/\\]gcloud)',
    'credential_theft_azure': r'(?:fs\.read(?:File)?Sync\([^)]*[\'"]\.azure|\.azure[/\\])',
    'trufflehog_usage': r'(?:spawn|exec|execSync)\([\'"]trufflehog',
    'github_exfiltration': r'(?:fetch|axios\.(?:post|get))\([\'"]https://api\.github\.com',
    'metadata_service': r'(?:fetch|axios\.get)\([\'"]https?://(?:169\.254\.169\.254|metadata\.google\.internal)',
    'ioc_files': r'fs\.writeFileSync\([^)]*[\'"](?:cloud|contents|environment|truffleSecrets|actionsSecrets)\.json',
    'double_base64': r'Buffer\.from\(Buffer\.from\([^)]+,\s*[\'"]base64[\'"]\)\.toString\(\)',
    'env_scraping': r'JSON\.stringify\(process\.env\)',
    'ci_detection': r'process\.env\.(?:GITHUB_ACTIONS|CI|BUILDKITE|CODEBUILD_BUILD_NUMBER|CIRCLE_SHA1|PROJECT_ID)',
    'home_destruction': r'fs\.(?:rm|rmdir)Sync\([^)]*(?:HOME|home|~)',
    'bun_install': r'(?:exec|execSync)\([\'"]curl\s+https://bun\.sh/install',
    'runner_registration': r'(?:fetch|axios\.post)\([^\)]*actions/runners/registration-token',
    'datadog_credentials': r'process\.env\.(?:DD_API_KEY|DATADOG_API_KEY|DD_APP_KEY)',
}

# Паттерны для GitHub Actions workflows
WORKFLOW_MALICIOUS_PATTERNS = {
    'discussion_injection': r'on:\s*discussion:.*\$\{\{\s*github\.event\.discussion\.body\s*\}\}',
    'self_hosted_runner': r'runs-on:\s*self-hosted',
    'formatter_workflow': r'formatter_\d+\.yml',
    'secrets_artifact': r'(?:secrets|credentials|cloud|environment|truffle).*\.(?:json|txt)',
}


def load_compromised_packages(update: bool = False) -> Dict[str, List[str]]:
    """Загрузка списка скомпрометированных пакетов"""

    # Попытка обновить из GitHub
    if update and not LOCAL_IOCS_FILE.exists():
        print("📥 Загрузка актуального списка IOCs из GitHub...")
        try:
            urllib.request.urlretrieve(DATADOG_IOCS_URL, LOCAL_IOCS_FILE)
            print(f"✅ Список обновлен: {LOCAL_IOCS_FILE}")
        except Exception as e:
            print(f"⚠️  Не удалось загрузить список: {e}")
            print("   Используется fallback список")

    # Загрузка из локального CSV
    if LOCAL_IOCS_FILE.exists():
        try:
            compromised = {}
            with open(LOCAL_IOCS_FILE, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    package_name = row['package_name']
                    versions = row['package_versions'].split(',')
                    # Очистка версий
                    versions = [v.strip() for v in versions]
                    compromised[package_name] = versions

            print(f"✅ Загружено {len(compromised)} скомпрометированных пакетов из IOCs")
            return compromised
        except Exception as e:
            print(f"⚠️  Ошибка чтения IOCs: {e}")

    print(f"⚠️  Используется fallback список ({len(FALLBACK_COMPROMISED_PACKAGES)} пакетов)")
    return FALLBACK_COMPROMISED_PACKAGES


class LockFileParser:
    """Парсер для различных типов lock файлов"""

    @staticmethod
    def parse_package_lock(lock_path: Path) -> Dict[str, str]:
        """Парсинг package-lock.json (npm)"""
        try:
            with open(lock_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            packages = {}

            # npm v1/v2 format
            if 'dependencies' in data:
                LockFileParser._extract_npm_v1_deps(data['dependencies'], packages)

            # npm v3 (lockfileVersion 3) format
            if 'packages' in data:
                for pkg_path, pkg_data in data['packages'].items():
                    if pkg_path and pkg_path != '':
                        pkg_name = pkg_path.replace('node_modules/', '')
                        if 'version' in pkg_data:
                            packages[pkg_name] = pkg_data['version']

            return packages
        except Exception as e:
            print(f"⚠️  Ошибка парсинга package-lock.json: {e}")
            return {}

    @staticmethod
    def _extract_npm_v1_deps(deps: Dict, packages: Dict[str, str]):
        """Рекурсивное извлечение зависимостей из npm v1/v2 формата"""
        for name, data in deps.items():
            if isinstance(data, dict) and 'version' in data:
                packages[name] = data['version']
                if 'dependencies' in data:
                    LockFileParser._extract_npm_v1_deps(data['dependencies'], packages)

    @staticmethod
    def parse_yarn_lock(lock_path: Path) -> Dict[str, str]:
        """Парсинг yarn.lock"""
        try:
            with open(lock_path, 'r', encoding='utf-8') as f:
                content = f.read()

            packages = {}
            pattern = r'"?([^"@\s]+)@[^"]*"?:\s*\n\s*version\s+"([^"]+)"'
            matches = re.findall(pattern, content)

            for pkg_name, version in matches:
                packages[pkg_name] = version

            return packages
        except Exception as e:
            print(f"⚠️  Ошибка парсинга yarn.lock: {e}")
            return {}

    @staticmethod
    def parse_pnpm_lock(lock_path: Path) -> Dict[str, str]:
        """Парсинг pnpm-lock.yaml (простой встроенный парсер без зависимостей)"""
        try:
            with open(lock_path, 'r', encoding='utf-8') as f:
                content = f.read()

            packages = {}

            # Простой парсинг для pnpm v6+ (секция packages:)
            # Формат: /package/version или /package@version
            in_packages_section = False
            for line in content.split('\n'):
                # Определяем секцию packages
                if line.strip() == 'packages:':
                    in_packages_section = True
                    continue
                
                # Выход из секции при новой top-level секции
                if in_packages_section and line and not line.startswith(' ') and not line.startswith('\t'):
                    in_packages_section = False
                
                if in_packages_section and line.strip():
                    # Ищем строки вида: '/package/version:' или '/package@version:'
                    match = re.match(r'\s+[\'"]?/(.+?)[@/](\d+\.\d+\.\d+[^\s:\'"]*)[\'":]', line)
                    if match:
                        pkg_name = match.group(1)
                        version = match.group(2)
                        packages[pkg_name] = version

            return packages
        except Exception as e:
            print(f"⚠️  Ошибка парсинга pnpm-lock.yaml: {e}")
            return {}


class ShaiHuludDetectorFinal:
    def __init__(self, project_path: str, update_iocs: bool = False, deep_scan: bool = True):
        self.project_path = Path(project_path)
        self.findings: List[Dict] = []
        self.all_packages: Dict[str, str] = {}
        self.compromised_packages = load_compromised_packages(update=update_iocs)
        self.deep_scan = deep_scan
        self.scanned_files = 0
        self.start_time = datetime.now()

    def scan(self) -> bool:
        """Выполнить полное сканирование проекта"""
        print(f"\n🔍 Сканирование проекта: {self.project_path}")
        print("=" * 70)

        if self.project_path.is_file():
            project_dir = self.project_path.parent
        else:
            project_dir = self.project_path

        # Сканирование зависимостей
        self._scan_dependencies(project_dir)
        
        # Глубокое сканирование файлов (если включено)
        if self.deep_scan:
            print(f"\n� Глубокое сканирование исходного кода...")
            self._scan_js_files(project_dir)
            self._scan_workflows(project_dir)
            self._scan_malicious_files(project_dir)

        return self._print_results()

    def _scan_dependencies(self, project_dir: Path):
        """Сканирование файлов зависимостей"""
        print(f"\n�📦 Поиск файлов зависимостей...")

        # Сканируем package.json
        package_json_path = project_dir / 'package.json'
        if package_json_path.exists():
            print(f"  ✓ package.json")
            self._scan_package_json(package_json_path)
            self.scanned_files += 1

        # Сканируем lock файлы
        lock_files_found = []

        package_lock_path = project_dir / 'package-lock.json'
        if package_lock_path.exists():
            print(f"  ✓ package-lock.json")
            lock_files_found.append('npm')
            packages = LockFileParser.parse_package_lock(package_lock_path)
            self._check_lock_packages(packages, 'package-lock.json')
            self.scanned_files += 1

        yarn_lock_path = project_dir / 'yarn.lock'
        if yarn_lock_path.exists():
            print(f"  ✓ yarn.lock")
            lock_files_found.append('yarn')
            packages = LockFileParser.parse_yarn_lock(yarn_lock_path)
            self._check_lock_packages(packages, 'yarn.lock')
            self.scanned_files += 1

        pnpm_lock_path = project_dir / 'pnpm-lock.yaml'
        if pnpm_lock_path.exists():
            print(f"  ✓ pnpm-lock.yaml")
            lock_files_found.append('pnpm')
            packages = LockFileParser.parse_pnpm_lock(pnpm_lock_path)
            self._check_lock_packages(packages, 'pnpm-lock.yaml')
            self.scanned_files += 1

        bun_lock_path = project_dir / 'bun.lockb'
        if bun_lock_path.exists():
            print(f"  ⚠️  bun.lockb (бинарный формат - не поддерживается)")

        if not lock_files_found and not package_json_path.exists():
            print(f"\n⚠️  Не найдено файлов зависимостей в {project_dir}")

        if self.all_packages:
            print(f"\n📊 Проверено пакетов: {len(self.all_packages)}")
        print(f"📊 База IOCs: {len(self.compromised_packages)} скомпрометированных пакетов")

    def _scan_js_files(self, project_dir: Path):
        """Сканирование JS/TS файлов на паттерны атаки"""
        # Паттерны для поиска JS/TS файлов
        patterns = ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx']
        
        js_files = []
        for pattern in patterns:
            for file_path in project_dir.glob(pattern):
                # Пропускаем node_modules и скрытые папки
                if 'node_modules' in file_path.parts or any(p.startswith('.') for p in file_path.parts[:-1]):
                    continue
                js_files.append(file_path)
        
        if not js_files:
            return
        
        print(f"  📄 Найдено {len(js_files)} JS/TS файлов для анализа...")
        
        for file_path in js_files:
            self._scan_js_file(file_path)
            self.scanned_files += 1

    def _scan_js_file(self, file_path: Path):
        """Сканирование одного JS/TS файла"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Проверка на индикаторы в содержимом
            for indicator in MALICIOUS_INDICATORS:
                if indicator in content:
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'type': 'malicious_indicator_in_file',
                        'file': str(file_path.relative_to(self.project_path)),
                        'indicator': indicator,
                        'message': f'Индикатор Shai-Hulud в файле: {indicator}'
                    })
            
            # Проверка на вредоносные паттерны
            for pattern_name, pattern_regex in JS_MALICIOUS_PATTERNS.items():
                matches = re.finditer(pattern_regex, content, re.MULTILINE | re.DOTALL)
                for match in matches:
                    # Определяем severity в зависимости от паттерна
                    severity = 'CRITICAL' if pattern_name in [
                        'credential_theft_git', 'credential_theft_npm', 'credential_theft_aws',
                        'trufflehog_usage', 'ioc_files', 'home_destruction', 'runner_registration'
                    ] else 'HIGH' if pattern_name in [
                        'github_exfiltration', 'metadata_service', 'bun_install'
                    ] else 'WARNING'
                    
                    # Получаем номер строки
                    line_num = content[:match.start()].count('\n') + 1
                    
                    self.findings.append({
                        'severity': severity,
                        'type': f'js_pattern_{pattern_name}',
                        'file': str(file_path.relative_to(self.project_path)),
                        'line': line_num,
                        'pattern': pattern_name,
                        'message': f'Обнаружен паттерн {pattern_name} (строка {line_num})'
                    })
        
        except Exception as e:
            # Игнорируем ошибки чтения файлов
            pass

    def _scan_workflows(self, project_dir: Path):
        """Сканирование GitHub Actions workflows"""
        workflows_dir = project_dir / '.github' / 'workflows'
        
        if not workflows_dir.exists():
            return
        
        workflow_files = list(workflows_dir.glob('*.yml')) + list(workflows_dir.glob('*.yaml'))
        
        if not workflow_files:
            return
        
        print(f"  🔧 Найдено {len(workflow_files)} workflow файлов...")
        
        for workflow_file in workflow_files:
            self._scan_workflow_file(workflow_file)
            self.scanned_files += 1

    def _scan_workflow_file(self, file_path: Path):
        """Сканирование workflow файла"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Проверка имени файла
            if file_path.name == 'discussion.yaml' or file_path.name == 'discussion.yml':
                self.findings.append({
                    'severity': 'CRITICAL',
                    'type': 'malicious_workflow_file',
                    'file': str(file_path.relative_to(self.project_path)),
                    'message': 'Обнаружен подозрительный workflow: discussion.yaml'
                })
            
            # Проверка на formatter workflow
            if re.match(r'formatter_\d+\.ya?ml', file_path.name):
                self.findings.append({
                    'severity': 'CRITICAL',
                    'type': 'malicious_workflow_file',
                    'file': str(file_path.relative_to(self.project_path)),
                    'message': f'Обнаружен подозрительный workflow: {file_path.name}'
                })
            
            # Проверка индикаторов
            for indicator in MALICIOUS_INDICATORS:
                if indicator in content:
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'type': 'malicious_indicator_in_workflow',
                        'file': str(file_path.relative_to(self.project_path)),
                        'indicator': indicator,
                        'message': f'Индикатор Shai-Hulud в workflow: {indicator}'
                    })
            
            # Проверка на вредоносные паттерны
            for pattern_name, pattern_regex in WORKFLOW_MALICIOUS_PATTERNS.items():
                if re.search(pattern_regex, content, re.MULTILINE | re.DOTALL):
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'type': f'workflow_pattern_{pattern_name}',
                        'file': str(file_path.relative_to(self.project_path)),
                        'pattern': pattern_name,
                        'message': f'Обнаружен паттерн {pattern_name} в workflow'
                    })
        
        except Exception as e:
            pass

    def _scan_malicious_files(self, project_dir: Path):
        """Поиск известных вредоносных файлов"""
        malicious_files = ['setup_bun.js', 'bun_environment.js']
        
        for mal_file in malicious_files:
            # Поиск файлов рекурсивно
            for found_file in project_dir.rglob(mal_file):
                # Пропускаем node_modules
                if 'node_modules' not in found_file.parts:
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'type': 'known_malicious_file',
                        'file': str(found_file.relative_to(self.project_path)),
                        'message': f'Обнаружен известный вредоносный файл: {mal_file}'
                    })
                    self.scanned_files += 1

    def _scan_package_json(self, package_json_path: Path):
        """Сканирование package.json"""
        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self._check_compromised_packages(data, 'package.json')
            self._check_malicious_scripts(data)
            self._check_file_references(data)
            self._check_repository_info(data)
        except Exception as e:
            print(f"❌ Ошибка чтения package.json: {e}")

    def _check_lock_packages(self, packages: Dict[str, str], source: str):
        """Проверка пакетов из lock файла"""
        for pkg_name, version in packages.items():
            self.all_packages[pkg_name] = version

            if pkg_name in self.compromised_packages:
                clean_version = re.sub(r'^[^0-9]*', '', version)

                if clean_version in self.compromised_packages[pkg_name]:
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'type': 'compromised_package_lock',
                        'source': source,
                        'package': pkg_name,
                        'version': version,
                        'message': f'[{source}] Скомпрометированный: {pkg_name}@{version}'
                    })

    def _check_compromised_packages(self, package_json: Dict, source: str):
        """Проверка зависимостей из package.json"""
        sections = ['dependencies', 'devDependencies', 'optionalDependencies']

        for section in sections:
            if section not in package_json:
                continue

            for package, version in package_json[section].items():
                if package in self.compromised_packages:
                    clean_version = re.sub(r'^[^0-9]*', '', version)

                    if clean_version in self.compromised_packages[package]:
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'type': 'compromised_package',
                            'section': section,
                            'package': package,
                            'version': version,
                            'message': f'[package.json] Скомпрометированный: {package}@{version}'
                        })

    def _check_malicious_scripts(self, package_json: Dict):
        """Проверка scripts секции"""
        if 'scripts' not in package_json:
            return

        scripts = package_json['scripts']

        for script_name, script_content in scripts.items():
            for indicator in MALICIOUS_INDICATORS:
                if indicator in script_content:
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'type': 'malicious_indicator',
                        'script': script_name,
                        'indicator': indicator,
                        'message': f'Индикатор Shai-Hulud: {indicator}'
                    })

            for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
                if re.search(pattern, script_content):
                    self.findings.append({
                        'severity': 'WARNING',
                        'type': 'suspicious_script',
                        'script': script_name,
                        'message': f'Подозрительный скрипт: {script_name}'
                    })

            if script_name in ['preinstall', 'postinstall', 'install']:
                if any(word in script_content.lower() for word in ['curl', 'wget', 'bun', 'github']):
                    self.findings.append({
                        'severity': 'HIGH',
                        'type': 'suspicious_lifecycle_script',
                        'script': script_name,
                        'message': f'Подозрительный {script_name}'
                    })

    def _check_file_references(self, package_json: Dict):
        """Проверка файловых ссылок"""
        for field in ['main', 'bin', 'browser']:
            if field in package_json:
                value = package_json[field]
                if isinstance(value, str):
                    for indicator in MALICIOUS_INDICATORS:
                        if indicator in value:
                            self.findings.append({
                                'severity': 'CRITICAL',
                                'type': 'malicious_file_reference',
                                'field': field,
                                'message': f'Подозрительный файл в "{field}": {value}'
                            })

    def _check_repository_info(self, package_json: Dict):
        """Проверка репозитория"""
        if 'repository' in package_json:
            repo = package_json['repository']
            repo_url = repo if isinstance(repo, str) else repo.get('url', '')

            if any(indicator in repo_url for indicator in ['Sha1-Hulud', 'SHA1HULUD']):
                self.findings.append({
                    'severity': 'CRITICAL',
                    'type': 'malicious_repository',
                    'message': 'Репозиторий Shai-Hulud!'
                })

    def _print_results(self) -> bool:
        """Вывод результатов"""
        elapsed_time = (datetime.now() - self.start_time).total_seconds()
        
        print(f"\n{'=' * 70}")
        print(f"📊 Сканирование завершено")
        print(f"{'=' * 70}")
        print(f"⏱️  Время: {elapsed_time:.2f}s")
        print(f"📄 Проверено файлов: {self.scanned_files}")
        print(f"📦 Проверено пакетов: {len(self.all_packages)}")
        
        if not self.findings:
            print("\n✅ Индикаторов Shai-Hulud 2.0 не обнаружено")
            print("✅ Проект безопасен")
            return True

        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        warnings = [f for f in self.findings if f['severity'] == 'WARNING']

        print(f"\n🚨 Обнаружено {len(self.findings)} проблем:")
        print(f"   ├─ 🔴 CRITICAL: {len(critical)}")
        print(f"   ├─ 🟠 HIGH: {len(high)}")
        print(f"   └─ 🟡 WARNING: {len(warnings)}\n")

        # Группировка по типам
        findings_by_type = {}
        for finding in self.findings:
            ftype = finding['type']
            if ftype not in findings_by_type:
                findings_by_type[ftype] = []
            findings_by_type[ftype].append(finding)

        # Детальный вывод
        print(f"{'=' * 70}")
        print("🔍 Детальные результаты:")
        print(f"{'=' * 70}\n")
        
        for finding in critical + high + warnings:
            emoji = "🔴" if finding['severity'] == 'CRITICAL' else "🟠" if finding['severity'] == 'HIGH' else "🟡"
            print(f"{emoji} [{finding['severity']}] {finding['type']}")
            print(f"   {finding['message']}")

            for key, value in finding.items():
                if key not in ['severity', 'type', 'message']:
                    print(f"   • {key}: {value}")
            print()

        if len(critical) > 0:
            print(f"{'=' * 70}")
            print("⚠️  КРИТИЧЕСКАЯ УГРОЗА ОБНАРУЖЕНА!")
            print(f"{'=' * 70}\n")
            print("🛡️  Немедленные действия:")
            print("1. 🔒 Изолируйте систему от сети")
            print("2. 🔑 Ротируйте все credentials:")
            print("   • GitHub tokens (Settings → Developer settings → Revoke all)")
            print("   • NPM tokens (npm token revoke --all)")
            print("   • AWS credentials (aws iam delete-access-key)")
            print("   • GCP credentials (gcloud auth revoke --all)")
            print("   • Azure credentials")
            print("3. 🔍 Проверьте GitHub на репозитории 'Sha1-Hulud: The Second Coming'")
            print("4. 🤖 Проверьте self-hosted runners с именем 'SHA1HULUD'")
            print("5. 🗑️  Удалите node_modules и переустановите чистые версии:")
            print("   rm -rf node_modules package-lock.json")
            print("   npm install --ignore-scripts")
            print("6. 📋 Проверьте .github/workflows/discussion.yaml")
            print("7. 📊 Проверьте логи на несанкционированные действия")
            print("\n📖 Подробнее: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/")

        return len(critical) == 0

    def generate_json_report(self, output_file: str = "shai-hulud-scan-report.json") -> None:
        """Генерация JSON отчёта"""
        report = {
            'scan_info': {
                'target': str(self.project_path),
                'timestamp': datetime.now().isoformat(),
                'elapsed_seconds': (datetime.now() - self.start_time).total_seconds(),
                'scanned_files': self.scanned_files,
                'scanned_packages': len(self.all_packages),
                'iocs_database_size': len(self.compromised_packages),
            },
            'summary': {
                'total_findings': len(self.findings),
                'critical': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
                'high': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'warning': len([f for f in self.findings if f['severity'] == 'WARNING']),
            },
            'findings': self.findings,
            'packages_checked': self.all_packages,
        }
        
        output_path = Path(output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 JSON отчёт сохранён: {output_path.absolute()}")


def scan_directory(directory: str, update_iocs: bool = False, deep_scan: bool = True) -> bool:
    """Рекурсивное сканирование директории"""
    directory_path = Path(directory)

    if not directory_path.exists():
        print(f"❌ Директория не существует: {directory}")
        sys.exit(1)

    # Поиск проектов с package.json
    projects = set()
    for package_json in directory_path.rglob('package.json'):
        # Пропускаем node_modules
        if 'node_modules' not in package_json.parts:
            projects.add(package_json.parent)

    if not projects:
        print(f"⚠️  Проекты с package.json не найдены в {directory}")
        return True

    print(f"\n📦 Найдено {len(projects)} проектов для сканирования")
    print(f"🔬 Режим: {'Глубокое сканирование' if deep_scan else 'Только зависимости'}\n")

    all_clean = True
    total_findings = 0
    
    for i, project_dir in enumerate(sorted(projects), 1):
        print(f"\n{'=' * 70}")
        print(f"Проект {i}/{len(projects)}: {project_dir.name}")
        print(f"{'=' * 70}")
        
        detector = ShaiHuludDetectorFinal(str(project_dir), update_iocs=update_iocs, deep_scan=deep_scan)
        is_clean = detector.scan()

        if not is_clean:
            all_clean = False
            total_findings += len(detector.findings)

    print(f"\n{'=' * 70}")
    print(f"📊 Итоговая статистика")
    print(f"{'=' * 70}")
    print(f"Всего проектов: {len(projects)}")
    print(f"Чистых проектов: {sum(1 for _ in projects) - (0 if all_clean else 1)}")
    print(f"Проблемных проектов: {0 if all_clean else 1}")
    print(f"Всего находок: {total_findings}")
    
    if all_clean:
        print("\n✅ Все проекты безопасны!")
        return True
    else:
        print("\n🚨 Обнаружены потенциальные угрозы!")
        return False


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Shai-Hulud 2.0 Scanner - комплексный детектор атаки Shai-Hulud 2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s ./my-project                    # Сканирование одного проекта
  %(prog)s ./package.json                  # Сканирование конкретного файла
  %(prog)s ~/projects --recursive          # Рекурсивное сканирование
  %(prog)s . --update-iocs                 # Обновить базу IOCs
  %(prog)s . --quick                       # Быстрое сканирование (только зависимости)
  %(prog)s . --json-report report.json     # Сохранить JSON отчёт

Уровни severity:
  🔴 CRITICAL - Прямые индикаторы атаки, требует немедленных действий
  🟠 HIGH     - Подозрительное поведение, требует проверки
  🟡 WARNING  - Потенциально опасные паттерны

Подробнее: https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0
        """
    )
    
    parser.add_argument('path', help='Путь к проекту, package.json или директории')
    parser.add_argument('--update-iocs', action='store_true',
                       help='Обновить список IOCs из GitHub (Datadog)')
    parser.add_argument('--quick', action='store_true',
                       help='Быстрое сканирование (только зависимости, без глубокого анализа кода)')
    parser.add_argument('--recursive', '-r', action='store_true',
                       help='Рекурсивное сканирование всех проектов в директории')
    parser.add_argument('--json-report', metavar='FILE',
                       help='Сохранить результаты в JSON файл')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0 (Final)')
    
    args = parser.parse_args()

    target_path = Path(args.path)
    deep_scan = not args.quick

    if not target_path.exists():
        print(f"❌ Невалидный путь: {args.path}")
        sys.exit(1)

    # Рекурсивное сканирование директории
    if args.recursive and target_path.is_dir():
        is_clean = scan_directory(args.path, update_iocs=args.update_iocs, deep_scan=deep_scan)
        sys.exit(0 if is_clean else 1)
    
    # Сканирование одного проекта
    if target_path.is_file() or target_path.is_dir():
        detector = ShaiHuludDetectorFinal(args.path, update_iocs=args.update_iocs, deep_scan=deep_scan)
        is_clean = detector.scan()
        
        # Сохранение JSON отчёта
        if args.json_report:
            detector.generate_json_report(args.json_report)
        
        sys.exit(0 if is_clean else 1)


if __name__ == "__main__":
    main()
