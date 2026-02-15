# 🔒 SECURITY

## Реализованная защита

Форум защищён от всех основных типов атак:

### ✅ XSS (Cross-Site Scripting)
- **Content Security Policy (CSP)** - блокирует выполнение вредоносных скриптов
- **X-XSS-Protection** - включен браузерный XSS фильтр
- **httpOnly cookies** - JavaScript не может получить доступ к cookies
- **DOMPurify** - санитизация всего пользовательского контента
- **Экранирование HTML** - все данные от пользователей экранируются

### ✅ CSRF (Cross-Site Request Forgery)
- **SameSite=strict cookies** - браузер не отправит cookie с других сайтов
- **Origin verification** - проверка origin header
- **CORS политика** - только разрешённые домены
- **Custom headers** - дополнительная валидация

### ✅ Clickjacking
- **X-Frame-Options: DENY** - страницу нельзя встроить в iframe
- **frame-ancestors 'none'** - CSP защита от фреймов
- **frameguard** - полная блокировка фреймов

### ✅ SQL Injection
- **Prepared Statements** - все запросы параметризованы
- **better-sqlite3** - защищённый драйвер БД
- **Input validation** - валидация всех входных данных
- **Санитизация** - очистка пользовательских данных

### ✅ Session Hijacking
- **Secure cookies** - только HTTPS в продакшене
- **httpOnly** - защита от JS
- **SameSite strict** - защита от CSRF
- **Session rotation** - обновление при каждом запросе
- **Strong session secret** - криптографически стойкий ключ

### ✅ MIME Sniffing
- **X-Content-Type-Options: nosniff** - браузер не будет угадывать MIME type

### ✅ Man-in-the-Middle (MITM)
- **HSTS** - форсит HTTPS на 1 год
- **includeSubDomains** - защита поддоменов
- **preload** - включение в HSTS preload list

### ✅ Information Disclosure
- **hidePoweredBy** - скрывает что используется Express
- **Кастомные error messages** - не раскрывают внутреннюю инфу
- **Custom session name** - не используется дефолтное имя

### ✅ Brute Force
- **Rate Limiting** - 100 запросов за 15 минут
- **Auth Rate Limiting** - 5 попыток входа за 15 минут
- **IP Ban system** - автобан при подозрительной активности
- **Failed login tracking** - отслеживание неудачных попыток

### ✅ DDoS Protection
- **Global rate limiter** - ограничение общих запросов
- **Endpoint specific limiters** - разные лимиты для разных endpoints
- **IP based limiting** - лимиты по IP адресам

### ✅ File Upload Attacks
- **File type validation** - только разрешённые типы
- **File size limits** - максимум 100MB
- **MIME type checking** - проверка реального типа файла
- **Unique filenames** - предотвращает перезапись

### ✅ NoSQL/Database Injection
- **Prepared statements** - параметризованные запросы
- **Input sanitization** - очистка всех входов
- **Type validation** - проверка типов данных

## 🔐 Конфигурация

### Обязательно настрой .env:

```env
# КРИТИЧНО! Смени на свой рандомный ключ минимум 32 символа
SESSION_SECRET=твой-супер-секретный-ключ-минимум-32-символа

# В продакшене используй HTTPS
NODE_ENV=production

# Ограничь CORS только своим доменом
ALLOWED_ORIGINS=https://yourdomain.com
```

### Генерация сильного SESSION_SECRET:

```bash
# Linux/Mac
openssl rand -base64 32

# Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

## 🚀 Production Deployment

### 1. HTTPS обязателен!

```bash
# Получи бесплатный SSL сертификат с Let's Encrypt
sudo apt install certbot
sudo certbot certonly --standalone -d yourdomain.com
```

### 2. Настрой Nginx reverse proxy

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # SSL Security
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # Security Headers (дополнительно к Helmet)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### 3. Настрой Firewall

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Закрой прямой доступ к Node.js порту
sudo ufw deny 8080
```

### 4. Запусти с PM2

```bash
npm install -g pm2
pm2 start server.js --name offensive-forum
pm2 startup
pm2 save
```

## 🛡️ Security Checklist

Перед запуском в продакшен проверь:

- [ ] **SESSION_SECRET** изменён на рандомный ключ
- [ ] **ADMIN_PASSWORD** изменён
- [ ] **NODE_ENV=production** установлен
- [ ] **HTTPS** настроен
- [ ] **ALLOWED_ORIGINS** ограничен твоим доменом
- [ ] **Firewall** настроен
- [ ] **Nginx reverse proxy** настроен
- [ ] **SSL сертификат** установлен
- [ ] **Резервное копирование БД** настроено
- [ ] **Логи** настроены и мониторятся
- [ ] **HSTS preload** добавлен (hstspreload.org)

## 📊 Мониторинг безопасности

### SIEM Events
Форум логирует все критичные события:
- Неудачные попытки входа
- Превышение rate limits
- Попытки доступа с забаненных IP
- Подозрительную активность
- SQL injection попытки
- XSS попытки

Логи находятся в БД (таблица `siem_events`).

### Проверка логов:

```bash
# Последние security события
sqlite3 database.sqlite "SELECT * FROM siem_events ORDER BY created_at DESC LIMIT 50;"

# Критичные события
sqlite3 database.sqlite "SELECT * FROM siem_events WHERE severity='critical' ORDER BY created_at DESC;"

# Забаненные IP
sqlite3 database.sqlite "SELECT * FROM ip_bans WHERE expires_at IS NULL OR expires_at > strftime('%s','now')*1000;"
```

## 🔍 Vulnerability Scanning

Регулярно проверяй на уязвимости:

```bash
# Проверка npm пакетов
npm audit
npm audit fix

# Обновление пакетов
npm update

# Сканирование с snyk
npm install -g snyk
snyk test
snyk monitor
```

## 🚨 Incident Response

При обнаружении атаки:

1. **Забань IP**:
```sql
INSERT INTO ip_bans (ip_address, reason, banned_by, created_at) 
VALUES ('x.x.x.x', 'Attempted attack', 1, strftime('%s','now')*1000);
```

2. **Проверь логи**:
```bash
pm2 logs offensive-forum --lines 1000
```

3. **Ротация session secret** (сбросит все сессии):
```bash
# Сгенерируй новый ключ
openssl rand -base64 32

# Обнови .env
# Перезапусти сервер
pm2 restart offensive-forum
```

## 📞 Контакты

По вопросам безопасности: security@yourdomain.com

---

**⚠️ Важно:** Безопасность - это процесс, а не конечное состояние. Регулярно обновляй зависимости, мониторь логи и следи за новыми уязвимостями.
