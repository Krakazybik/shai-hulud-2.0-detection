#!/usr/bin/env python3
"""
Скрипт для проверки package.json на наличие скомпрометированных пакетов из атаки Shai-Hulud 2.0
"""

import json
import sys
import os
import re
from typing import Dict, List, Set, Tuple
from pathlib import Path

# Известные скомпрометированные пакеты и версии на основе исследований
# Источники: Wiz, Datadog, SafeDep, Aikido
COMPROMISED_PACKAGES = {
    # Zapier packages
    "zapier-platform-core": ["0.15.0", "0.15.1"],
    "zapier-platform-cli": ["18.0.0", "18.0.1"],
    "zapier-sdk": ["1.0.0"],
    
    # AsyncAPI packages (36+ пакетов)
    "@asyncapi/specs": ["7.6.4"],
    "@asyncapi/parser": ["3.3.1"],
    "@asyncapi/modelina": ["4.3.0"],
    
    # PostHog packages
    "posthog-node": ["4.2.1"],
    "posthog-js": ["1.165.0"],
    
    # Postman packages
    "@postman/postman-mcp-cli": ["0.1.0"],
    
    # ENS Domains packages
    "@ensdomains/ensjs": ["4.1.0"],
    
    # Browserbase
    "@browserbasehq/sdk": ["1.5.0"],
}

# Индикаторы компрометации в package.json
MALICIOUS_INDICATORS = [
    "setup_bun.js",
    "bun_environment.js",
    "SHA1HULUD",
    "Sha1-Hulud",
    "Shai-Hulud",
]

# Подозрительные preinstall/postinstall скрипты
SUSPICIOUS_SCRIPT_PATTERNS = [
    r"curl.*https?://[^\s]+",  # Скачивание из интернета
    r"wget.*https?://[^\s]+",
    r"bash.*<<.*EOF",  # Встроенные bash скрипты
    r"node.*setup_bun",
    r"bun.*bun_environment",
    r"npm.*publish",  # Автоматическая публикация
]


class ShaiHuludDetector:
    def __init__(self, package_json_path: str):
        self.package_json_path = Path(package_json_path)
        self.findings: List[Dict] = []
        
    def load_package_json(self) -> Dict:
        """Загрузка и парсинг package.json"""
        try:
            with open(self.package_json_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Ошибка чтения {self.package_json_path}: {e}")
            sys.exit(1)
    
    def check_compromised_packages(self, package_json: Dict) -> None:
        """Проверка зависимостей на наличие известных скомпрометированных версий"""
        dependencies_sections = ['dependencies', 'devDependencies', 'optionalDependencies']
        
        for section in dependencies_sections:
            if section not in package_json:
                continue
                
            for package, version in package_json[section].items():
                if package in COMPROMISED_PACKAGES:
                    # Очистка версии от префиксов (^, ~, >=, etc.)
                    clean_version = re.sub(r'^[^0-9]*', '', version)
                    
                    if clean_version in COMPROMISED_PACKAGES[package]:
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'type': 'compromised_package',
                            'section': section,
                            'package': package,
                            'version': version,
                            'message': f'Обнаружен скомпрометированный пакет: {package}@{version}'
                        })
                    elif any(v in version for v in COMPROMISED_PACKAGES[package]):
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'type': 'compromised_package',
                            'section': section,
                            'package': package,
                            'version': version,
                            'message': f'Возможно скомпрометированная версия: {package}@{version}'
                        })
    
    def check_malicious_scripts(self, package_json: Dict) -> None:
        """Проверка scripts секции на наличие подозрительных команд"""
        if 'scripts' not in package_json:
            return
        
        scripts = package_json['scripts']
        
        # Проверка на индикаторы Shai-Hulud
        for script_name, script_content in scripts.items():
            for indicator in MALICIOUS_INDICATORS:
                if indicator in script_content:
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'type': 'malicious_indicator',
                        'script': script_name,
                        'indicator': indicator,
                        'message': f'Обнаружен индикатор Shai-Hulud в скрипте "{script_name}": {indicator}'
                    })
            
            # Проверка на подозрительные паттерны
            for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
                if re.search(pattern, script_content):
                    self.findings.append({
                        'severity': 'WARNING',
                        'type': 'suspicious_script',
                        'script': script_name,
                        'pattern': pattern,
                        'content': script_content[:100],
                        'message': f'Подозрительный скрипт "{script_name}": найден паттерн {pattern}'
                    })
            
            # Особое внимание preinstall/postinstall
            if script_name in ['preinstall', 'postinstall', 'install']:
                if any(word in script_content.lower() for word in ['curl', 'wget', 'bun', 'github']):
                    self.findings.append({
                        'severity': 'HIGH',
                        'type': 'suspicious_lifecycle_script',
                        'script': script_name,
                        'content': script_content,
                        'message': f'Подозрительный {script_name} скрипт с сетевыми операциями'
                    })
    
    def check_file_references(self, package_json: Dict) -> None:
        """Проверка на подозрительные файлы в проекте"""
        # Проверка main, bin и других файловых ссылок
        file_fields = ['main', 'bin', 'browser']
        
        for field in file_fields:
            if field in package_json:
                value = package_json[field]
                if isinstance(value, str):
                    for indicator in MALICIOUS_INDICATORS:
                        if indicator in value:
                            self.findings.append({
                                'severity': 'CRITICAL',
                                'type': 'malicious_file_reference',
                                'field': field,
                                'value': value,
                                'message': f'Подозрительная ссылка в поле "{field}": {value}'
                            })
    
    def check_repository_info(self, package_json: Dict) -> None:
        """Проверка информации о репозитории"""
        if 'repository' in package_json:
            repo = package_json['repository']
            repo_url = repo if isinstance(repo, str) else repo.get('url', '')
            
            # Проверка на подозрительные репозитории
            if 'Sha1-Hulud' in repo_url or 'SHA1HULUD' in repo_url:
                self.findings.append({
                    'severity': 'CRITICAL',
                    'type': 'malicious_repository',
                    'repository': repo_url,
                    'message': 'Обнаружена ссылка на репозиторий Shai-Hulud!'
                })
    
    def scan(self) -> bool:
        """Выполнить полное сканирование"""
        print(f"🔍 Сканирование: {self.package_json_path}")
        print("=" * 70)
        
        package_json = self.load_package_json()
        
        # Запуск всех проверок
        self.check_compromised_packages(package_json)
        self.check_malicious_scripts(package_json)
        self.check_file_references(package_json)
        self.check_repository_info(package_json)
        
        # Вывод результатов
        if not self.findings:
            print("✅ Индикаторов Shai-Hulud 2.0 не обнаружено")
            return True
        
        # Группировка по severity
        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        warnings = [f for f in self.findings if f['severity'] == 'WARNING']
        
        print(f"\n🚨 Обнаружено {len(self.findings)} проблем:")
        print(f"   ├─ CRITICAL: {len(critical)}")
        print(f"   ├─ HIGH: {len(high)}")
        print(f"   └─ WARNING: {len(warnings)}\n")
        
        # Детальный вывод
        for finding in critical + high + warnings:
            emoji = "🔴" if finding['severity'] == 'CRITICAL' else "🟠" if finding['severity'] == 'HIGH' else "🟡"
            print(f"{emoji} [{finding['severity']}] {finding['type']}")
            print(f"   {finding['message']}")
            
            # Дополнительная информация
            for key, value in finding.items():
                if key not in ['severity', 'type', 'message']:
                    print(f"   • {key}: {value}")
            print()
        
        return len(critical) == 0
    
    def generate_report(self, output_file: str = "shai-hulud-scan-report.json") -> None:
        """Генерация JSON отчёта"""
        report = {
            'scan_target': str(self.package_json_path),
            'total_findings': len(self.findings),
            'critical': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
            'high': len([f for f in self.findings if f['severity'] == 'HIGH']),
            'warning': len([f for f in self.findings if f['severity'] == 'WARNING']),
            'findings': self.findings
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 Отчёт сохранён: {output_file}")


def scan_directory(directory: str) -> None:
    """Рекурсивное сканирование директории на наличие package.json"""
    directory_path = Path(directory)
    
    if not directory_path.exists():
        print(f"❌ Директория не существует: {directory}")
        sys.exit(1)
    
    package_json_files = list(directory_path.rglob('package.json'))
    
    if not package_json_files:
        print(f"⚠️  Файлы package.json не найдены в {directory}")
        return
    
    print(f"📦 Найдено {len(package_json_files)} файлов package.json\n")
    
    all_clean = True
    for package_json in package_json_files:
        detector = ShaiHuludDetector(str(package_json))
        is_clean = detector.scan()
        
        if not is_clean:
            all_clean = False
        
        print()
    
    if all_clean:
        print("✅ Все проверки пройдены успешно")
        sys.exit(0)
    else:
        print("🚨 Обнаружены потенциальные угрозы!")
        print("\nРекомендации:")
        print("1. Немедленно изолируйте затронутые системы")
        print("2. Ротируйте все credentials (GitHub, NPM, AWS, GCP, Azure)")
        print("3. Проверьте логи на наличие несанкционированных действий")
        print("4. Обновите скомпрометированные пакеты до безопасных версий")
        print("5. Проверьте GitHub на наличие созданных репозиториев 'Sha1-Hulud: The Second Coming'")
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print("Использование:")
        print(f"  {sys.argv[0]} <path-to-package.json>")
        print(f"  {sys.argv[0]} <directory>  # рекурсивное сканирование")
        print("\nПримеры:")
        print(f"  {sys.argv[0]} ./package.json")
        print(f"  {sys.argv[0]} ./projects")
        sys.exit(1)
    
    target = sys.argv[1]
    target_path = Path(target)
    
    if target_path.is_file() and target_path.name == 'package.json':
        detector = ShaiHuludDetector(target)
        is_clean = detector.scan()
        
        if not is_clean:
            detector.generate_report()
            sys.exit(1)
    elif target_path.is_dir():
        scan_directory(target)
    else:
        print(f"❌ Невалидный путь: {target}")
        print("Укажите путь к package.json или директории")
        sys.exit(1)


if __name__ == "__main__":
    main()
