# ⚡ ZeusVPN

مدیر کانفیگ با تم بنفش زئوس — ترکیبی از ظاهر اپ‌های **V2Ray / Happ / V2Box** به‌صورت یک صفحه وب (PWA).

> ⚠️ ZeusVPN هیچ سروری ارائه نمی‌دهد و چیزی را تغییر نمی‌دهد؛ فقط **ظاهر و ابزار مدیریت** است. کانفیگ‌های خودت (vmess/vless/trojan/ss/hysteria2/tuic یا اشتراک) را وارد می‌کنی و ZeusVPN آن‌ها را مدیریت، تست و به اپ‌های واقعی (Happ / V2Box / v2rayNG / Hiddify) منتقل می‌کند.

## امکانات

- 🎨 تم بنفش زئوس با لوگوی آذرخش
- 📥 ایمپورت لینک کانفیگ (هر خط یکی)، فایل txt، متن Base64 و لینک اشتراک
- 🧠 پارسر واقعی: `vmess` (Base64 JSON)، `vless`، `trojan`، `ss`، `hysteria2/hy2`، `tuic`
- 📶 تست واقعی دسترسی سرور (HTTPS reachability + هندشیک WebSocket برای نودهای ws+tls)
- 🔳 QR کد برای هر کانفیگ + اشتراک‌گذاری
- 🚀 دکمه‌های deep-link: `happ://import`، `v2box://install-sub`، `hiddify://import`، `v2rayng://install-config`
- 📤 خروجی: فایل اشتراک Base64 و JSON خروجی Xray
- 🤖 PWA اندروید: با Chrome → «Add to Home screen» مثل اپ نصب می‌شود (آفلاین هم بالا می‌آید)
- 💾 ذخیره محلی در مرورگر (localStorage) — هیچ داده‌ای جایی ارسال نمی‌شود

## اجرا

آدرس صفحه: `https://Matin-mohebi.github.io/zeusvpn/`

## دانلود کلاینت‌های اتصال

| اپ | پلتفرم | لینک |
|---|---|---|
| Happ | Android / iOS / Desktop | [GitHub Releases](https://github.com/Happ-proxy/happ-android/releases) · [happ.su](https://www.happ.su/main) |
| v2rayNG | Android | [GitHub Releases](https://github.com/2dust/v2rayNG/releases) |
| V2Box | Android / iOS | [Google Play](https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box) |
| Hiddify | همه پلتفرم‌ها | [GitHub Releases](https://github.com/hiddify/hiddify-app/releases) |

## نکته امنیتی

اگر توکن گیت‌هابت را جایی به اشتراک گذاشته‌ای، بعد از استقرار آن را از
**GitHub → Settings → Developer settings → Personal access tokens** حذف/بازه‌گذاری کن.
