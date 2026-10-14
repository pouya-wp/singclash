# SingClash

A middleware that turns a sing-box subscription into a Clash.Meta (Mihomo) profile for **FlClash**, with a minimal web panel.

میدل‌ور تبدیل سابسکریپشن **sing-box (JSON)** به پروفایل **Clash.Meta / Mihomo (YAML)** برای FlClash، به‌همراه پنل وب.

## چطور کار می‌کند

1. FlClash لینک `/sub?token=…` را باز می‌کند.
2. سرور لینک سابسکریپشن اصلی را با هدر `User-Agent: sing-box` (قابل تغییر در پنل) واکشی می‌کند تا JSON کامل ساین‌باکس برگردد.
3. Outboundها به پروکسی‌های Mihomo تبدیل می‌شوند و کانفیگ‌های دستی هم به آن‌ها اضافه می‌شوند.
4. همه‌ی پروکسی‌ها در یک گروه `url-test` (تست خودکار پینگ) قرار می‌گیرند. یک گروه `select` هم برای انتخاب دستی هست.
5. هدر `subscription-userinfo` (حجم مصرفی و تاریخ انقضا) از سرور اصلی به FlClash منتقل می‌شود.

اگر سرور اصلی در دسترس نباشد و هیچ کانفیگ دستی هم نباشد، خطای 502 برگردانده می‌شود. این‌طوری FlClash پروفایل قبلی را نگه می‌دارد و آن را با یک پروفایل خالی عوض نمی‌کند.

## اجرای محلی

```bash
npm install
npm run dev        # http://localhost:3000
```

تنظیمات در `config.json` ذخیره می‌شوند. این فایل بار اول خودکار ساخته می‌شود و در git نیست، چون لینک و توکن شما داخلش است.

| متغیر محیطی | توضیح |
|---|---|
| `PORT` | پورت (پیش‌فرض 3000) |
| `PANEL_PASSWORD` | رمز پنل (Basic Auth؛ نام کاربری دلخواه است) |
| `PUBLIC_URL` | آدرس عمومی برای ساخت لینک خروجی، اگر پشت ریورس‌پراکسی هستید |
| `CONFIG_PATH` | مسیر دیگری برای `config.json` |

## دیپلوی روی Vercel

فایل‌سیستم Vercel فقط‌خواندنی است و بعد از هر اجرا پاک می‌شود. برای همین، روی Vercel تنظیمات در **Upstash Redis** (پلن رایگان) ذخیره می‌شوند.

1. ریپو را در Vercel ایمپورت کنید (**Add New → Project**). Framework را روی **Other** بگذارید. بقیه‌ی تنظیمات بیلد را دست نزنید؛ `vercel.json` همه چیز را تنظیم می‌کند.
2. در پروژه: **Storage → Marketplace → Upstash (Redis) → Create** و دیتابیس را به پروژه وصل کنید. متغیرهای `KV_REST_API_URL` و `KV_REST_API_TOKEN` خودکار اضافه می‌شوند (`UPSTASH_REDIS_REST_URL` و `UPSTASH_REDIS_REST_TOKEN` هم پشتیبانی می‌شوند).
3. در **Settings → Environment Variables**، متغیر `PANEL_PASSWORD` را بسازید. روی Vercel این متغیر اجباری است، چون پنل روی اینترنت عمومی است.
4. دوباره **Redeploy** کنید، `https://<project>.vercel.app` را باز کنید، رمز را وارد کنید (نام کاربری دلخواه)، تنظیمات را ذخیره کنید و لینک خروجی را در FlClash بگذارید.

> اگر دامنه‌ی `vercel.app` روی اینترنت شما در دسترس نیست، یک دامنه‌ی شخصی به پروژه وصل کنید (**Settings → Domains**).

## فرمت‌های پشتیبانی‌شده

**سابسکریپشن اصلی:** JSON ساین‌باکس (`outbounds` و `endpoints`)؛ برای اطمینان، YAML کلش و لیست لینک (ساده یا base64) هم قبول می‌شود.

پروتکل‌های قابل تبدیل از ساین‌باکس: VLESS (شامل Reality و Vision)، VMess، Trojan، Shadowsocks (شامل obfs، v2ray-plugin و ShadowTLS از طریق detour)، Hysteria، Hysteria2 (شامل port hopping و salamander)، TUIC، AnyTLS، WireGuard (هم فرم outbound و هم endpoint)، SSH، HTTP و SOCKS.
ترنسپورت‌ها: ws، httpupgrade، grpc، http/h2. مالتی‌پلکس (smux) هم پشتیبانی می‌شود.

**کانفیگ‌های دستی** (می‌توانید در یک متن با هم ترکیب کنید):

```
vless://uuid@host:443?security=reality&sni=…&pbk=…&sid=…#Name
vmess://…   trojan://…   ss://…   hysteria2:// (hy2://)   hysteria://   tuic://   anytls://   socks://
Home Snell = snell, 1.2.3.4, 443, psk=secret, version=4, obfs=http, obfs-host=bing.com
- name: my-node
  type: trojan
  server: example.com
  port: 443
  password: secret
```

JSON یک یا چند outbound ساین‌باکس هم قبول می‌شود.

> Mihomo فقط Snell نسخه‌ی ۱ تا ۳ را پشتیبانی می‌کند. نسخه‌ی ۴ و ۵ خودکار به ۳ تبدیل می‌شوند، که با سرورهای v4/v5 سازگار است. در پیش‌نمایش برای این تبدیل هشدار می‌بینید.

## توسعه

```bash
npm test            # تست‌های مبدل
npm run build:css   # بعد از تغییر کلاس‌های Tailwind در public/
```

`public/styles.css` از قبل ساخته شده و در ریپو هست. پس پنل بدون CDN و بدون مرحله‌ی بیلد اجرا می‌شود.
