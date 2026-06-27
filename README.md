На основе PDF — вот финальный ReadMe с точными скриншотами и шагами как вы делали:

---

# 🍯 Honeypot Investigation — CTF Writeup

**Категория:** Forensics | **Очки:** 1000  
**Платформа:** RTEAM  
**Подсказка:** Возможно это Akira атаковала наш Veeam...  
**Референс:** [CISA Advisory AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)

---

## 📋 Задание

> Кто-то попался на наш ханипот. Логи сохранились, кроме связанных с запуском cmd.
> 1. Какой потенциальный IP адрес атакующего?
> 2. Что они потенциально эксплуатировали для доступа? (.........exe)
> 3. С помощью какого аккаунта они дальше закрепились?

---

## 🛠️ Инструменты

- [Docker Desktop для Windows](https://www.docker.com/products/docker-desktop/)
- [docker-elk](https://github.com/deviantony/docker-elk) — готовый ELK стек
- [Node.js для Windows](https://nodejs.org/)
- [elasticsearch-dump](https://github.com/elasticsearch-dump/elasticsearch-dump) — импорт логов в ELK
- Kibana Discover — анализ логов

---

## ⚙️ Подготовка окружения

### Шаг 1: Поднимаем ELK в Docker

Устанавливаем [Docker Desktop](https://www.docker.com/products/docker-desktop/), перезагружаем ПК. Открываем **PowerShell**:

```powershell
git clone https://github.com/deviantony/docker-elk.git
cd docker-elk
docker-compose up -d
```

После запуска в Docker Desktop должны быть запущены 4 контейнера:
- `logstash-1`
- `kibana-1`
- `elasticsearch-1`
- `docker-elk`

Kibana доступна по адресу: http://localhost:5601  
Логин: `elastic` / Пароль: `changeme`

---

### Шаг 2: Распаковываем логи

Скачиваем архив с Google Drive и распаковываем. Внутри `dump.zip` находятся 22 файла JSON (~22 GB):

```
dump_ds-logs-elastic_agent.endpoint_security-rteamoffice-2026.01.09-000014.json
dump_ds-logs-elastic_agent.endpoint_security-rteamoffice-2026.01.14-000015.json
dump_ds-logs-elastic_agent.filebeat-rteamoffice-2026.01.09-000014.json
dump_ds-logs-endpoint.events.library-rteamoffice-2026.01.14-000015.json
dump_ds-logs-endpoint.events.network-rteamoffice-2026.01.12-000014.json
dump_ds-logs-endpoint.events.security-rteamoffice-2026.01.09-000013.json
dump_ds-logs-endpoint.events.security-rteamoffice-2026.01.14-000014.json
dump_ds-logs-system.security-rteamoffice-2026.01.14-000015.json
dump_ds-logs-system.security-rteamoffice-2026.01.09-000014.json
dump_ds-logs-windows.powershell_operational-rteamoffice-2026.01.09-000010.json
dump_ds-logs-windows.powershell_operational-rteamoffice-2026.01.14-000011.json
dump_ds-logs-windows.windows_defender-rteamoffice-2026.01.09-000013.json
... и другие
```

---

### Шаг 3: Устанавливаем elasticsearch-dump

```powershell
npm install -g elasticdump
```

### Шаг 4: Импортируем логи в ELK

Для каждого файла запускаем команду в PowerShell (пример):

```powershell
elasticdump `
  --input="dump_ds-logs-system.security-rteamoffice-2026.01.14-000015.json" `
  --output="http://elastic:changeme@localhost:9200/honeypot-logs" `
  --type=data `
  --limit=10000
```

Повторяем для всех 22 файлов. Процесс выглядит так:
```
starting dump
got 10000 objects from source file (offset: 0)
sent 10000 objects, 0 offset, to destination elasticsearch, wrote 10000
got 10000 objects from source file (offset: 10000)
...
```

---

### Шаг 5: Создаём Index Pattern в Kibana

1. Открываем http://localhost:5601
2. **Stack Management** → **Index Patterns** → **Create index pattern**
3. Вводим: `honeypot-logs*`
4. Time field: `@timestamp`
5. Нажимаем **Create**

---

## 🔍 Структура логов

| Лог файл | Что содержит | Зачем нужен |
|----------|-------------|-------------|
| `system.security` | Входы/выходы, создание пользователей | Кто и когда заходил, брутфорс |
| `endpoint.events.security` | Процессы, сетевые подключения | Какой .exe запускался |
| `powershell_operational` | PowerShell команды | Что делал атакующий после взлома |
| `windows.windows_defender` | Срабатывания антивируса | Что Defender поймал |

---

## 🎯 Решение

### Вопрос 1: IP атакующего

Открываем **Kibana → Discover**, ищем события с `winlog.event_id: 4625` (неудачные попытки входа):

```
winlog.event_id: "4625"
```

Кликаем на поле **`source.ip`** в левой панели → смотрим **Top values**:

| IP | % |
|----|---|
| **85.116.125.143** | 28.1% |
| 194.38.21.200 | 24.9% |
| 194.145.227.233 | 21.2% |
| 149.50.10712 | 14.0% |
| 185.243.98.13 | 7.3% |
| 197.254.253.106 | 2.7% |

Подтверждаем — фильтруем по IP и проверяем:

```
source.ip: "85.116.125.143" AND winlog.event_id: "4624"
```

**✅ Ответ: `85.116.125.143`**

---

### Вопрос 2: Что эксплуатировали (.exe)

Ищем процессы связанные с Veeam:

```
process.name: *Veeam*
```

Кликаем на поле **`process.name`** в левой панели → **Top values**:

| Process | % |
|---------|---|
| **VeeamAuth.exe** | **94.2%** |
| Veeam.Backup.Manager.exe | 3.8% |
| VeeamDeploymentSvc.exe | 2.0% |

`VeeamAuth.exe` доминирует с 94.2% — это и есть точка входа.

**Почему VeeamAuth.exe?**  
Уязвимость **CVE-2023-27532** в Veeam Backup & Replication позволяет через `VeeamAuth.exe` получить зашифрованные credentials из базы данных без аутентификации, используя порт 9401.

**✅ Ответ: `VeeamAuth.exe`**

---

### Вопрос 3: Аккаунт закрепления

Ищем события добавления в группу (Event ID 4732):

```
winlog.event_id: 4732
```

**Найден 1 документ** — Jan 13, 2026 @ 20:33:44

Раскрываем запись и видим:
```
winlog.event_data.MemberSid: S-1-5-21-3650124714-2865276185-3030817660-501
Group: Administrators (S-1-5-32-544)
```

> SID заканчивающийся на **`-501`** = встроенный аккаунт **Guest**

Проверяем активацию аккаунта (Event ID 4722):

```
winlog.event_id: 4722
```

**Найден 1 документ** — Jan 13, 2026 @ 20:33:41

**Хронология атаки 13 января 2026:**

| Время (UTC) | Event ID | Действие |
|-------------|----------|----------|
| 20:33:41 | 4722 | Активация отключённого аккаунта `Guest` |
| 20:33:44 | 4732 | Добавление `Guest` в группу `Administrators` |

**✅ Ответ: `Guest`**

---

## 🗂️ Финальные ответы

| # | Вопрос | Ответ |
|---|--------|-------|
| 1 | IP атакующего | `85.116.125.143` |
| 2 | Эксплуатируемый .exe | `VeeamAuth.exe` |
| 3 | Аккаунт закрепления | `Guest` |

---

## 🔎 Дополнительные находки (бонус для кураторов)

| Параметр | Значение |
|----------|----------|
| Хост-жертва | `veeambackup` |
| ОС жертвы | Windows Server 2016 Standard (build 14393.1884) |
| IP жертвы | `91.224.74.122` |
| Облако | OpenStack, зона `ALA-1` |
| CVE | CVE-2023-27532 |
| Тип атаки | Authentication Bypass → Credential Dump → Privilege Escalation |
| Группировка | Akira Ransomware |
| Время атаки | 13 января 2026 @ 20:33 UTC |

---

## 📖 Полезные ссылки

- [CISA Advisory AA24-109A — Akira Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)
- [CVE-2023-27532 — Veeam Authentication Bypass](https://www.cvedetails.com/cve/CVE-2023-27532/)
- [docker-elk](https://github.com/deviantony/docker-elk)
- [elasticsearch-dump](https://github.com/elasticsearch-dump/elasticsearch-dump)
- [Docker Desktop для Windows](https://www.docker.com/products/docker-desktop/)
