# ZAP

DAST: menguji app yang sedang jalan dari luar lewat HTTP, tanpa membaca kode.

- Image ghcr.io/zaproxy/zaproxy:stable (image lama owasp/zap2docker-* sudah deprecated).
- Scan: zap-baseline.py, pasif, ke Juice Shop di network Docker internal.
- docker run --rm -t --network zapnet-int -v "$(pwd)/reports/raw:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://juice:3000 -J zap-baseline.json -r zap-baseline.html

## Persiapan: jaringan untuk scan

### Baseline itu pasif, tapi tetap mengirim request
Baseline tidak mengirim payload serangan. Tapi spider tetap meng-crawl semua link dan bisa submit form, jadi endpoint GET yang mengubah state (misalnya /logout atau /delete?id=1) tetap bisa terpicu. Yang pasif hanya analisisnya.

### Full scan hanya ke target milik sendiri
Full scan menjalankan active scan dan mengirim payload seperti SQLi dan XSS. Itu bisa merusak data dan dianggap serangan nyata. Tanpa izin tertulis (scope/RoE) termasuk akses ilegal (UU ITE Pasal 30 dan 33). Active scan juga mengirim ribuan request, jadi ke sistem sendiri pun diarahkan ke staging, bukan production.

### Kenapa network internal
Container ZAP tidak bisa memakai 127.0.0.1 untuk menjangkau app, karena 127.0.0.1 di dalam container adalah container itu sendiri. Ada dua jalur:
- --network host: ZAP berbagi network dengan host. Paling mudah, isolasi paling lemah. Action resmi zaproxy/action-baseline memakai jalur ini.
- User-defined network: ZAP dan Juice Shop di satu network, target pakai nama container (http://juice:3000). Ini yang kupilih.

Di network biasa, ZAP bisa menjangkau lebih dari Juice Shop: semua port semua container di network itu, host lewat gateway, dan internet. docker network connect juga menambah network, bukan memindahkan. Jadi aku pakai docker network create --internal zapnet-int. Container di network internal hanya bisa bicara dengan sesama container di network itu. Isolasinya baru berlaku kalau semua network non-internal dilepas. Trade-off-nya, browser di host tidak bisa membuka Juice Shop lagi.

### Verifikasi isolasi (Docker 29.1.3)
- Cek -p diabaikan: container uji dengan -p 127.0.0.1:3001:3000 di zapnet-int tidak membuka port di host. Kolom Ports cuma 3000/tcp tanpa panah, dan curl ke 127.0.0.1:3001 gagal. -p diterima tanpa error tapi diam-diam diabaikan. Konfigurasi yang terlihat benar belum tentu aktif.
- Cek tidak ada internet: curl https://google.com gagal dengan exit 6 (Could not resolve host), karena DNS internal Docker tidak meneruskan nama luar. curl https://1.1.1.1 gagal dengan exit 7 setelah 0 ms, artinya tidak ada route keluar.
- Cek antar container: curl http://juice:3000 dari container di zapnet-int menghasilkan 200 OK.
- Cek host tidak terjangkau: curl http://172.21.0.1:80 gagal dengan exit 28 (timeout 5 detik), artinya paket dibuang firewall.

Arti error curl ternyata beda-beda. Gagal seketika (exit 7, 0 ms) berarti tidak ada route. Timeout (exit 28) berarti paket dikirim tapi dibuang diam-diam. Connection refused (juga exit 7, pesannya beda) berarti paket sampai tapi tidak ada yang listen. Jadi baca pesannya, bukan cuma angkanya.

## Apa yang ditemukan

Hasil: FAIL-NEW 0, WARN-NEW 7, PASS 61, exit 2. Tujuh WARN itu dari scan pertama yang masih punya internet. Di network internal, report JSON cuma berisi 3 alert, karena 4 rule hilang (lihat insight).

| Kelompok | Rule | Risk | Catatan |
|---|---|---|---|
| Kandidat kerentanan | 10098 Cross-Domain Misconfiguration | Medium | dipicu Access-Control-Allow-Origin: * |
| Hardening | 10038 CSP Header Not Set | Medium | lapisan tambahan terhadap XSS, tidak bisa dieksploitasi sendiri |
| Hardening | 10063 Deprecated Feature Policy Header Set | Low, beta | header Feature-Policy yang deprecated |
| Hardening | 90004 Insufficient Site Isolation (Spectre) | Low, beta | varian COEP missing |
| Informational | 10109 Modern Web Application | Informational | app adalah SPA, spider klasik kemungkinan tidak melihat semua route |
| Informational | 10049 Storable and Cacheable Content | Informational, beta | Cache-Control: public, max-age=0 |
| Petunjuk | 10110 Dangerous JS Functions | Low, beta | pola fungsi yang bisa jadi penyebab XSS |

Temuan yang tidak dilaporkan ZAP tapi kutemukan sendiri:
- Stack trace di halaman 403 /ftp/encrypt.pyc.
- Directory listing /ftp.

## Cara menganalisa

### Mengelompokkan alert
Untuk tiap alert kutanya empat hal berurutan, berhenti di jawaban ya yang pertama:
1. Ini menjelaskan app atau scan-nya, bukan risiko? Kalau ya, informational. Petunjuknya kolom Risk sudah Informational.
2. Penyerang bisa memakainya langsung tanpa bug lain? Kalau ya atau mungkin, kandidat kerentanan yang wajib diverifikasi.
3. Ini lapisan pertahanan yang hilang, yang baru berpengaruh kalau ada bug lain? Kalau ya, hardening. Nama rule biasanya berbunyi Header Not Set, Missing, atau Deprecated.
4. Ini pola mencurigakan yang baru bisa dipastikan dengan membaca kode? Kalau ya, petunjuk.

Contohnya CSP masuk hardening karena tanpa XSS, CSP yang hilang tidak bisa dieksploitasi.

### Bedah 10098: ACAO *

| Pertanyaan | Jawaban |
|---|---|
| Pemicu | Access-Control-Allow-Origin: * di semua response. Sumbernya server.ts:183-184, app.options('*', cors()) dan app.use(cors()) tanpa opsi |
| Arti header | website mana pun boleh membaca response Juice Shop lewat JavaScript, selama request dikirim tanpa kredensial |
| Cara login frontend | token disimpan di localStorage (login.component.ts:110) dan cookie token (login.component.ts:113). request.interceptor.ts:16 mengirim Authorization: Bearer dari localStorage |
| Cara backend membaca token | campuran. isAuthorized (lib/insecurity.ts:52) hanya membaca header Authorization. Beberapa route membaca cookie (currentUser.ts, dataErasure.ts, updateUserProfile.ts, userProfile.ts, dan dua route upload gambar profil) |
| Bisa curi sesi user yang login? | tidak lewat ACAO * saja |
| Prioritas | rendah untuk Juice Shop yang memang publik. Naik kalau app yang sama jalan di jaringan internal |

Kenapa tidak bisa mencuri sesi:
- Route yang pakai header: website jahat tidak bisa membaca token dari localStorage milik origin lain, dan browser tidak menambahkan header Authorization secara otomatis.
- Route yang pakai cookie: cookie baru ikut kalau request memakai credentials: 'include'. Untuk request seperti itu, CORS melarang membaca response yang header-nya ACAO *. Origin harus ditulis persis dan Access-Control-Allow-Credentials: true harus ada. Aturan ini dari spesifikasi CORS, berlaku di semua website.
- CORS hanya memblok pembacaan response, bukan pengiriman request. CSRF di route berbasis cookie itu masalah terpisah.

Risiko nyata ACAO *: data yang bisa dibaca tanpa login bisa diambil website mana pun lewat browser pengunjungnya. Kalau app jalan di intranet, website luar yang dibuka karyawan bisa membaca app internal lewat browser karyawan itu. Konfigurasi yang benar-benar berbahaya adalah origin yang dipantulkan dari header Origin ditambah Allow-Credentials: true.

### 10110 Dangerous JS Functions: bukan noise
- main.js berisi 10 panggilan bypassSecurityTrust (8 Html, 2 Url). Fungsi Angular ini mematikan sanitizer bawaan.
- Sumbernya 9 baris di frontend/src/app. Dua di antaranya baris rentan challenge: search-result.component.ts:146 (parameter search dari URL langsung dirender) dan search-result.component.ts:113 (deskripsi produk dari API).
- ZAP hanya melihat pola dan tidak tahu data mana yang dikendalikan penyerang. Contohnya queryParam di search berasal dari URL (berbahaya), sedangkan captcha di data-export berasal dari server. Untuk membedakannya perlu baca kode dari source ke sink.
- Semgrep tidak melaporkan satu pun dari 9 baris itu. Rule beta ZAP menemukan petunjuk yang terlewat oleh SAST.

### Stack trace di /ftp/encrypt.pyc
URL aneh /juice-shop/node_modules/express/lib/router/index.js:286:9 di hasil spider bukan file asli. Itu satu frame stack trace di halaman error 403, dan spider membaca teks path itu sebagai link. Yang bocor:
- Nama app dan framework Express ^4.22.1 (tanda ^ berarti range dari package.json, bukan versi terpasang).
- Runtime Node.js, dari frame node:fs.
- Aturan filter: hanya .md dan .pdf yang boleh diunduh.
- Path instalasi /juice-shop/ dan struktur build (build/routes/fileServer.js).
- Lokasi persis pengecekan filter, fungsi verify di fileServer.js baris 68.
- Middleware serve-index yang membuat directory listing /ftp.

ZAP tidak melaporkannya walaupun rule Application Error Disclosure (90022) dan Debug Error Messages (10023) ter-load. Pola deteksinya cuma untuk PHP, ASP.NET, Java, IIS, dan pesan error database. Tidak ada pola untuk stack trace Node.js atau Express.

## Insight

### Isolasi bisa mematikan rule tanpa tanda
zap-baseline.py tanpa -silent menjalankan ZAP dengan -addonupdate -addoninstall pscanrulesBeta, karena image stable tidak membawa rule beta. Di network internal tidak ada internet, jadi install gagal. Satu-satunya jejak di zap.log adalah "Check for updates call failed". Empat rule beta hilang: 10049, 10063, 10110, 90004. Scan tetap selesai dengan exit 2 dan tanpa error di console.

Semua ERROR di zap.log adalah call home yang gagal (check for updates dan telemetry), yang sekaligus bukti isolasinya bekerja. Pelajarannya: hardening jaringan bisa memotong coverage scanner diam-diam. Hitung jumlah rule yang di-load, jangan cuma lihat exit code.

Cara dapat rule beta tanpa membuka internet: bikin image sendiri FROM ghcr.io/zaproxy/zaproxy:stable dengan pscanrulesBeta di-install saat build, lalu scan dengan -z "-silent". Rule terkunci saat build, jadi hasil scan bisa diulang, tapi image harus di-build ulang berkala. Default ZAP yang mengunduh add-on terbaru di setiap run juga risiko supply chain: hasil berubah tanpa kode berubah, dan kalau server add-on disusupi, kodenya langsung jalan di scanner.

### Exit code dan report bisa tidak sinkron
Exit code baseline: 1 kalau ada FAIL, 2 kalau ada WARN tanpa -I, 0 kalau hanya PASS, 3 kalau error lain (dicek dari source /zap/zap-baseline.py). Scan pertama sempat kucatat exit 0 padahal ada 7 WARN, jadi itu salah ukur. Exit code dihitung dari file summary internal, bukan dari report JSON, jadi gate yang membaca report JSON bisa melihat hasil berbeda dari exit code.

| Flag | Fungsi |
|---|---|
| -t | target |
| -r / -J | report HTML / JSON |
| -I | WARN tidak menghasilkan exit 2. Isi report tetap berisi WARN |
| -m | durasi spider dalam menit (default 1) |
| -g / -c | -g membuat file config rule, -c memakai config itu untuk set tiap rule ke IGNORE/WARN/FAIL. Ini cara tuning noise di ZAP |
| -j | AJAX spider dengan browser headless |

### Rating ZAP tidak kenal konteks
ZAP melabeli 10098 Medium tanpa tahu cara app menyimpan login dan siapa yang bisa menjangkau app. Rule berbasis signature juga hanya menemukan pola yang sudah ditulis. ZAP bahkan meng-crawl path dari stack trace itu tapi tidak mengenalinya sebagai kebocoran.

### Blind spot baseline
- SPA: spider klasik hanya membaca link di HTML dan tidak menjalankan JavaScript. Route Angular (#/...) dibuat JavaScript, jadi tidak terlihat. Ini masalah penemuan URL, bukan pasif vs aktif. Active scan hanya menyerang URL yang sudah ditemukan. Solusinya AJAX spider (-j), yang tetap bisa dipakai di baseline.
- Directory listing /ftp tidak dilaporkan karena Directory Browsing (ID 0) rule active. Ketemunya lewat active scan atau membuka /ftp langsung.
- Stack trace Node.js/Express tidak punya pola deteksi.
- Tanpa login: basket, profil, dan halaman admin tidak diuji.
- Hanya pasif: SQLi di routes/search.ts yang ditemukan Semgrep tidak ketemu di baseline.
- Endpoint API yang tidak di-link dari HTML (/rest/..., /api/...) tidak ditemukan spider. Perlu definisi OpenAPI dan zap-api-scan.py.
- Logika bisnis dan IDOR (jumlah negatif di basket, saldo wallet, data milik user lain) tidak bisa dideteksi tool mana pun. Butuh dua akun dan review manual.
- Jumlah instance cuma batas bawah, karena rule pasif berhenti setelah 10 alert (maxAlertsPerRule).

## Untuk fase berikutnya
- Image ZAP sendiri dengan pscanrulesBeta di-install saat build, scan dengan -z "-silent".
- Gate: exit 1 untuk FAIL, 2 untuk WARN, 3 untuk error. Tuning rule lewat -g dan -c. Jangan pakai -I tanpa alasan.
- Script Fase 4: jangan cuma baca report JSON. Cek juga jumlah rule yang di-load.
- Pertimbangkan AJAX spider (-j), scan dengan login, dan zap-api-scan.py.
- Di CI pilihan jaringannya beda, karena runner GitHub Actions adalah VM sekali pakai yang punya internet.
