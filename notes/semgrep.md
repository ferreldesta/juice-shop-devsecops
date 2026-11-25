# Semgrep

SAST: membaca kode sumber dan mencari pola bug, termasuk melacak data dari source ke sink.

- Versi 1.184.0, scan tanggal 2026-11-14. Isi registry pack berubah dari waktu ke waktu, jadi versi dan tanggal harus dicatat.
- Ruleset p/typescript (mayoritas repo TypeScript) dan p/owasp-top-ten (kerentanan Juice Shop mayoritas masuk Top 10). p/owasp-top-ten multi-bahasa, jadi ada juga temuan di YAML GitHub Actions, Terraform, dan .npmrc.
- Output di reports/raw/semgrep.json dan semgrep.sarif. Cukup satu run dengan --json-output=FILE dan --sarif-output=FILE.

## Apa yang ditemukan

43 temuan dan 54 errors. Errors adalah file yang gagal dianalisis, bukan temuan.

| Severity | Jumlah |
|---|---|
| WARNING | 28 |
| ERROR | 13 |
| MEDIUM | 2 |

MEDIUM berasal dari rule supply chain (npm-missing-minimum-release-age) yang memakai skala berbeda.

| Rule | Jumlah |
|---|---|
| github-actions-mutable-action-tag | 7 |
| express-sequelize-injection | 6 |
| run-shell-injection | 5 |
| insecure-load-balancer-tls-version | 5 |
| express-check-directory-listing | 5 |
| aws-subnet-has-public-ip-address | 5 |
| express-res-sendfile | 4 |
| npm-missing-minimum-release-age | 2 |
| hardcoded-jwt-secret | 1 |
| gha-curl-pipe-shell | 1 |
| express-open-redirect | 1 |
| code-string-concat | 1 |

| Kelas | Jumlah | Path |
|---|---|---|
| Server produksi | 14 | routes/ (8 file), server.ts (5), lib/insecurity.ts (1) |
| Non-produksi: snippet coding challenge | 10 | data/static/codefixes/ |
| Infra/config | 19 | .github/workflows/ (13), terraform/ dan infrastructure/terraform/ (4), .npmrc dan frontend/.npmrc (2) |

File infra/config tetap berisiko. run-shell-injection di workflow CI bisa dipakai mencuri secret atau GITHUB_TOKEN (supply chain). File Terraform berasal dari challenge "Vulnerable Infrastructure", jadi sengaja ditanam.

## Cara menganalisa

1. Hitung dan kelompokkan per severity, rule, dan folder dulu.
2. Klasifikasi per path: produksi, non-produksi, atau infra/config. Cek jenis file dulu baru folder, karena frontend/.npmrc itu config, bukan kode browser.
3. Triage satu temuan penting sampai tuntas, dari source ke sink (pakai --dataflow-traces).
4. Putuskan noise mau dibuang lewat apa.
5. Cek errors, karena itu bagian kode yang tidak diperiksa.
6. Cari false negative: bandingkan lokasi bug yang pasti ada (marker vuln-code-snippet) dengan isi report.

### Triage routes/search.ts:23

Rule express-sequelize-injection (ERROR, CWE-89, confidence HIGH).

| Langkah | Line | Kode | Peran |
|---|---|---|---|
| Source | 21 | criteria = req.query.q | input user dari query string |
| Transformasi | 22 | criteria.substring(0, 200) | hanya memotong panjang, bukan sanitizer |
| Sink | 23 | models.sequelize.query("... LIKE '%${criteria}%' ...") | criteria disisipkan langsung ke string SQL |

Verdict true positive. criteria masuk ke SQL tanpa parameterisasi dan tanpa dibersihkan. Batas 200 karakter tidak menolong karena payload UNION muat di bawah 200 karakter. Marker vuln-code-snippet memang menandai challenge, tapi verdict tetap harus dari flow, karena repo nyata tidak punya marker.

### False negative: bug yang lolos

Marker vuln-code-snippet kupakai sebagai ground truth, lalu kubandingkan dengan path di report (comm -23). Ada 5 file yang punya bug tapi tidak dilaporkan: app.routing.ts, search-result.component.ts, lib/codingChallenges.ts, routes/chat.ts, routes/updateProductReviews.ts. Hipotesis awalku "gagal parsing" ternyata salah: kelimanya ada di paths.scanned dan tidak ada di errors. Semgrep membaca kodenya, tapi tidak ada rule yang cocok.

Tiga yang kubedah:
- app.routing.ts (tokenSaleChallenge): route rahasia disembunyikan dengan obfuscation di kode frontend. Kode frontend dikirim ke browser, jadi siapa pun bisa men-decode-nya. Ini security through obscurity (CWE-656), cacat desain, bukan pola kode. Tidak ada source dan sink yang bisa dipegang rule taint.
- updateProductReviews.ts (forgedReviewChallenge): user yang login diambil, tapi tidak dipakai untuk membatasi review mana yang boleh diubah. Update hanya difilter dengan req.body.id. Ini IDOR.
- updateProductReviews.ts (noSqlReviewsChallenge): body {"id": {"$ne": -1}, "message": "hacked"} membuat filter { _id: { $ne: -1 } }, artinya semua review cocok. Dengan multi: true semua review diubah. NoSQL injection.

## Insight

### Exit code Semgrep
Default exit 0 walaupun ada temuan, karena Semgrep scanner umum yang temuannya lebih sering FP dan sebagian cuma best practice. Untuk gagal saat ada temuan pakai --error. Error tool punya kode sendiri (2 fatal, 3 invalid target, 4 invalid pattern, dst.), jadi error tetap ketahuan. Kalau lupa --error, temuan tidak pernah memblokir apa pun, SQLi baru pun pipeline tetap hijau. Gitleaks kebalikannya: leak dan error sama-sama 1, jadi gate bisa merah terus karena noise.

Gate yang realistis: --error dibatasi ke --severity ERROR, ditambah --baseline-commit supaya PR hanya gagal kalau ada temuan baru.

### Source, sink, sanitizer
- Source: titik yang dikendalikan penyerang (req.query, req.body, header).
- Sink: operasi yang berbahaya kalau datanya berbahaya (query SQL, exec, render HTML).
- Sanitizer: yang membuat data aman untuk sink tertentu. Tergantung konteks: HTML escape menolong XSS tapi tidak berguna untuk SQL. substring() bukan sanitizer.

### Kenapa parameterized query berhasil
Masalahnya bukan input dikirim ke SQL, tapi input disambung ke dalam teks SQL. Parser tidak bisa membedakan mana yang ditulis developer dan mana yang dikirim penyerang. Parameterized query memisahkan dua saluran itu: struktur query sudah ditetapkan sebelum data masuk, lalu nilai parameter diperlakukan sebagai literal. Nama tabel, kolom, dan ORDER BY tidak bisa diparameterisasi, jadi untuk itu pakai allowlist.

### Cara kerja NoSQL operator injection
Aku belum pernah pakai NoSQL, jadi ini yang paling lama kupahami.
- SQL menerima teks, lalu parser database membangun pohon sintaksnya. Penyerang harus mengubah teks (pakai tanda kutip) supaya pohonnya berubah.
- Mongo/MarsDB langsung menerima pohonnya dalam bentuk object filter. Key yang diawali $ adalah operator.
- express.json() mengubah body JSON jadi object JavaScript, dan JSON bisa membawa object, bukan cuma string. {"id": "abc123"} jadi filter satu review, {"id": {"$ne": -1}} jadi filter semua review. Kodenya sama, yang berubah tipe inputnya. Penyerang mengirim struktur, bukan sintaks. Query string juga bisa (?id[$ne]=1) karena Express mem-parse-nya jadi object.
- Operator harus ada di dalam nilai field. Body {"$ne": -1} di level atas tidak jalan, karena req.body.id jadi kosong.
- typeof === 'string' menutupnya karena string tidak punya key, jadi tidak bisa membawa operator. Prinsipnya sama dengan parameterized query: input dipaksa tetap jadi data. Secara umum: validasi tipe per field (zod, joi), atau buang key yang diawali $ (express-mongo-sanitize, sanitizeFilter di Mongoose).
- Perbaikan untuk route ini: wajibkan req.body.id berupa string, lalu tambahkan author: user.data.email ke filter. Kondisi author sekaligus menutup IDOR-nya.

### Semgrep hanya menemukan yang dimodelkan rule-nya
Semua rule injection yang muncul sink-nya Sequelize. Tidak ada rule untuk reviewsCollection.update() milik MarsDB. Ini celah coverage rule, bukan batas teknologinya, dan bisa ditutup dengan custom taint rule (source req.body, sink $COLL.update($FILTER, ...), sanitizer cek typeof).

IDOR beda cerita. Bug-nya adalah ketiadaan pengecekan, dan Semgrep tidak tahu data mana milik siapa karena itu aturan bisnis. Race condition juga susah karena tergantung timing antar request. DAST pun jarang menemukan IDOR karena butuh dua akun. Biasanya IDOR ketemu lewat pentest manual.

### Membuang noise: .semgrepignore
data/static/codefixes/ di-ignore bukan karena bersih (isinya justru penuh bug), tapi karena bukan kode produksi.

| Cara | Kelebihan | Kekurangan |
|---|---|---|
| .semgrepignore | tersimpan di repo, konsisten di lokal dan CI | siapa pun yang bisa commit bisa menyembunyikan kode dari scanner; membuat file ini menimpa pola ignore default |
| --exclude | cepat untuk eksperimen | hidup di command line, kalau lupa hasilnya beda |
| nosemgrep | presisi per baris, alasan bisa ditulis | harus ditulis di setiap baris, tidak cocok untuk satu folder |

Risiko utama .semgrepignore adalah insider. Kontrolnya: CODEOWNERS plus branch protection supaya perubahan file ini wajib di-approve tim security, path dibuat sempit dan tiap baris ada alasannya, lalu ditinjau berkala.

### Errors adalah blind spot

| Jenis | Jumlah | Lokasi | Penilaian |
|---|---|---|---|
| PartialParsing | 35 | workflow, codefixes, dan file produksi frontend (payment, wallet, deluxe-user, dll.) | yang di frontend produksi perlu diwaspadai |
| Syntax error | 16 | data/static/codefixes/ | wajar, snippet memang tidak lengkap |
| Timeout | 3 | frontend/src/assets/private/three.js | wajar, library vendor besar |

File yang gagal di-parse lalu 0 temuan bukan berarti aman, artinya tidak diperiksa. Parsing error levelnya WARN, jadi exit code tetap 0. Pilihan kebijakan: --strict (paling aman tapi berisik), bersihkan sumber error dengan exclude vendor dan snippet supaya error yang tersisa jadi sinyal nyata, dan review manual file produksi yang terus gagal di-parse.

## Untuk fase berikutnya
- Buat .semgrepignore untuk data/static/codefixes/. Salin dulu pola ignore default Semgrep.
- Gate: --error dengan --severity ERROR dan --baseline-commit.
- Satu run untuk JSON dan SARIF.
- Opsional: custom taint rule untuk sink MarsDB, lalu buktikan bug NoSQL jadi tertangkap.
- routes/login.ts:34 belum di-triage. Polanya sama dengan search.ts.
