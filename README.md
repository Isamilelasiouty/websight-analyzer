# 🔍 Website Performance & Security Analyzer

أداة Python متقدمة لتحليل مواقع الويب وكشف مشاكل الأداء والأمان والسيو.

---

## ✨ ما الذي تكتشفه الأداة؟

### 🔒 Security Headers
| الهيدر | الخطر لو غائب |
|--------|--------------|
| Content-Security-Policy | هجمات XSS |
| Strict-Transport-Security | SSL Stripping |
| Referrer-Policy | تسريب بيانات المستخدمين |
| Permissions-Policy | وصول غير مصرح للكاميرا/GPS |
| X-Frame-Options | Clickjacking |
| X-Content-Type-Options | MIME Sniffing |

### ⚡ Performance
- عدد الـ Requests وتصنيفها بالنوع
- وقت تحميل كل ملف (أبطأ الملفات)
- أكبر الملفات حجماً
- إجمالي حجم JS و CSS
- First Contentful Paint و DOM Load time

### 🖼️ Images
- كشف الصور بدون Lazy Loading
- أسماء ملفات بالعربي (ضعيفة للـ SEO)
- صور بتنسيقات قديمة (JPG/PNG بدل WebP)

### 🎨 Font Awesome
- كشف تحميل المكتبة الكاملة
- ملفات woff/woff2 الزيادة

### 🔗 SEO
- وجود Canonical Tags
- بارامتر srsltid (Duplicate Content)
- Render-blocking resources

---

## 🚀 التثبيت

```bash
# 1. استنسخ الريبو
git clone https://github.com/yourusername/website-analyzer.git
cd website-analyzer

# 2. ثبّت المتطلبات
pip install -r requirements.txt

# 3. ثبّت متصفح Chromium
python -m playwright install chromium
```

---

## 📖 الاستخدام

```bash
# تحليل أي موقع
python analyzer.py https://arabian-traveler.com

# تحديد اسم ملف التقرير
python analyzer.py https://mysite.com --output my-report.html

# حفظ النتائج بصيغة JSON أيضاً
python analyzer.py https://mysite.com --json

# بدون https
python analyzer.py arabian-traveler.com
```

---

## 📊 التقرير

بعد التحليل، هتلاقي ملف `report.html` في نفس المجلد.
افتحه في أي متصفح وهتشوف:

- **النتيجة الكلية** من 100
- **المشاكل المكتشفة** مرتبة حسب الخطورة مع شرح كل مشكلة وطريقة حلها
- **Security Headers** جدول بحالة كل هيدر
- **أبطأ الملفات** في التحميل مع رسم بياني
- **أكبر الملفات** حجماً
- **إحصائيات JS/CSS/Images**

---

## 📈 نظام النقاط

| المشكلة | الخصم |
|---------|-------|
| 🔴 Critical | -20 نقطة |
| 🟡 Warning | -10 نقاط |
| 🔵 Info | -2 نقاط |

**الدرجات:**
- A = 90-100 ✅
- B = 75-89 🟢
- C = 60-74 🟡
- D = 40-59 🟠
- F = أقل من 40 🔴

---

## 🛠️ المتطلبات

- Python 3.8+
- اتصال بالإنترنت
- Chromium (يتثبت تلقائياً مع playwright)

---

## 📝 License

MIT License
