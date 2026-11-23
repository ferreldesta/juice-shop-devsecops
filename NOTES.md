# NOTES

## Fase 0: Setup

### Isi repo

| File/folder | Isi |
|---|---|
| README.md | Gambaran umum OWASP Juice Shop. |
| package.json | Metadata project, scripts yang bisa dijalankan, dependencies, dan versi engine (Node) yang dibutuhkan. |
| Dockerfile | Instruksi untuk membangun Docker image. |
| .gitignore | File/folder yang tidak boleh masuk ke repo git. |
| .dockerignore | File/folder yang tidak dikirim ke build context, jadi tidak ikut tersalin ke image. |
| routes/ | Logika yang menangani tiap endpoint API, bukan hanya routing. |
| frontend/ | Kode frontend. |
| data/ | Database dan seed data (user, produk, challenge). |
| .github/workflows/ | Workflow GitHub Actions (16 file): CI/test, release, CodeQL, dan otomasi repo (stale, lock, compliance). Contoh: codeql-analysis.yml jalan setiap push ke branch mana pun dan setiap pull request. |

### Dockerfile

- Stage: ada dua.
  1. installer (base node:24): install dependency, bersih-bersih, dan atur izin file.
  2. Image akhir.
- Multi-stage: stage akhir hanya mengambil folder /juice-shop dari installer (COPY --from=installer --chown=65532:0 /juice-shop .).
  - Yang ikut ke image akhir: kode app dan node_modules produksi, karena dibutuhkan saat runtime. devDependencies tidak ikut karena npm install --omit=dev, bukan karena multi-stage.
  - Yang tertinggal di installer: isi node:24 (bash, apt, curl, git, compiler), tool global (typescript dan cyclonedx-npm, terpasang di /usr/local/lib, bukan di /juice-shop), dan cache npm.
  - Untung dari sisi security: penyerang tidak menemukan tool di image akhir, paket OS lebih sedikit sehingga CVE di Trivy dan yang perlu di-patch juga lebih sedikit, dan tool build tidak ikut ke produksi.
  - Jebakan: multi-stage hanya menyaring yang ada di luar /juice-shop. File di build context seperti .env tetap tersalin ke /juice-shop lalu terbawa ke image akhir. Pencegahnya .dockerignore, bukan multi-stage.
- Base image akhir: gcr.io/distroless/nodejs24-debian13. Distroless mengurangi attack surface. Tapi karena isinya sedikit (tanpa shell), debugging jadi susah.
- User: USER 65532, yaitu UID non-root.

### Checkpoint

1. Kenapa user di grup docker setara root?
Daemon Docker berjalan sebagai root. Siapa pun yang bisa mengakses socket Docker bisa menjalankan container dengan -v /:/host, jadi bisa mount apa pun dari host, termasuk seluruh filesystem. Docker hanya mengecek apakah boleh pakai socket dan tidak mengecek apakah boleh baca /etc/

2. Kenapa tidak boleh shallow clone?
gitleaks memindai seluruh riwayat commit, termasuk secret yang sudah ditimpa. Shallow clone hanya mengambil sebagian riwayat, jadi sisanya tidak terperiksa dan repo terlihat bersih padahal tidak.

3. Kenapa repo baru harus kosong total sebelum push?
Kalau repo baru sudah berisi file (README, lisensi) atau commit lain, riwayatnya berbeda dengan riwayat lokal. Push akan ditolak, atau aku terpaksa force push dan merusak riwayat.

4. Kenapa Actions dimatikan dulu?
Supaya workflow bawaan yang tidak kumengerti tidak ikut jalan. Workflow itu juga butuh secret yang tidak kupunya, jadi akan gagal. Repo akan penuh tanda merah dan kuota Actions terpakai.

5. Keputusan soal workflow bawaan?
Dinonaktifkan. Aku akan merakit workflow sendiri, dengan workflow asli sebagai referensi.

6. Temuan Dockerfile?
Lihat bagian Dockerfile di atas.

7. Kenapa port diikat ke 127.0.0.1?
Supaya app hanya bisa diakses dari laptop sendiri (lokal), sehingga orang di Wi-Fi yang sama tidak bisa mengakses web tersebut.

8. Apa masalahnya kalau node_modules/ lokal ikut masuk build?
Build context jadi terlalu besar dan lambat. node_modules/ lokal dikompilasi untuk OS dan versi Node di laptop, yang kemungkinan berbeda dengan di container. Image juga jadi bergantung pada isi laptop, bukan pada package.json, sehingga hasil SCA mungkin tidak akurat.

9. Kenapa scan image buatan sendiri, bukan image resmi?
Image resmi tidak mencerminkan commit yang kubuat atau base image yang kutarik. Prinsipnya: scan artifact yang kukirim, bukan milik orang lain atau dari waktu yang berbeda.

10. Kenapa menghapus history bukan cara memperbaiki secret yang bocor?
Secret yang pernah bocor harus dianggap sudah dicuri, dan menghapus riwayat tidak menarik kembali salinan yang sudah ada di tempat lain. Yang harus dilakukan:
- Rotate: cabut secret lama di sumbernya, lalu buat yang baru.
- Audit: cek log penggunaan secret lama, apakah sempat dipakai orang lain.
- Setelah itu baru bersihkan history, lalu pasang pencegah, misalnya gitleaks di pre-commit atau CI.

11. Apa beda bare dan non-bare repo, dan kenapa backup-nya bare?
Bare repo hanya berisi isi .git/ (riwayat dan data), tanpa working tree, jadi tidak bisa diedit langsung. Non-bare adalah hasil git init atau git clone biasa, yang punya working tree. Backup dibuat bare karena:
- Tidak ada duplikasi file, jadi lebih ringkas.
- Tidak akan teredit secara tidak sengaja.
- Bare repo adalah tujuan push yang wajar. Push ke branch yang sedang di-checkout di non-bare repo ditolak secara default (receive.denyCurrentBranch). Server Git seperti GitHub juga menyimpan repo dalam bentuk bare.

## Fase 1: Scan manual

### Langkah 1: gitleaks

- Versi: gitleaks 8.30.1 (binary dari GitHub Releases). Versi apt 8.16 dihapus karena rule-nya lama dan belum punya subcommand git/dir.
- Scan: seluruh history (sekitar 24 ribu commit, semua ref) selesai dalam 5.41 detik. Output mentah di reports/raw/gitleaks.json.
- Exit code: 1 berarti ada temuan, 0 berarti tidak ada temuan. Error tool juga keluar dengan 1, jadi gate harus bisa membedakannya.
- Total temuan: 225.

| Rule | Jumlah |
|---|---|
| generic-api-key | 164 |
| jwt | 54 |
| private-key | 7 |

Cara triage: kelompokkan per path, jangan dibuka satu per satu. 196 dari 225 temuan (87%) ada di file test/spec, yaitu data fixture, bukan kredensial nyata.

Klasifikasi 7 temuan private-key:
- 6 sengaja ditanam sebagai challenge Juice Shop (lib/insecurity.js, terraform/networking.tf, infrastructure/terraform/networking.tf, test/files/passkeyVictimCredential.json). Ada penandanya, misalnya vuln-code-snippet atau nama file insecurity.
- 1 true positive: vagrant/.vagrant/machines/default/virtualbox/private_key. Ini kunci SSH yang dibuat otomatis oleh Vagrant dan seharusnya di-ignore. Ter-commit pada 2017-03-03 ("Include latest changes"), lalu dihapus di hari yang sama ("Remove vagrant folder"). Commit itu hanya ada di branch gh-pages, jadi baru terdeteksi karena backup dibuat dengan --mirror (semua ref). Dampaknya rendah karena kunci ini hanya untuk VM lokal, tapi klasifikasinya tetap true positive. Sekarang vagrant/.vagrant/ sudah ada di .gitignore.

Temuan di file yang sudah dihapus: 47 dari 64 file unik (73%) yang memicu temuan sudah tidak ada di working tree.

Kenapa secret di file yang sudah dihapus tetap masalah?
Menghapus file hanya membuat commit baru yang menyatakan "file ini sudah tidak ada". Commit lama yang memuat file itu tetap utuh di database Git, dan isinya masih bisa dibaca oleh siapa pun yang punya clone, fork, atau mirror. Kalau hanya memindai file saat ini (gitleaks dir), kunci Vagrant tidak akan ketemu. Kunci itu baru muncul lewat gitleaks git, yang menelusuri semua commit di semua ref. Karena salinan secret sudah tersebar dan tidak bisa ditarik kembali, menghapus file atau membersihkan history saja tidak cukup. Secret harus dianggap sudah dicuri, jadi langkah utamanya adalah rotate dan audit (lihat Q10).

### Langkah 2: Semgrep

- Versi: semgrep 1.184.0. Isi registry pack berubah dari waktu ke waktu, jadi versi dan tanggal scan (2026-11-14) harus dicatat.
- Ruleset: p/typescript, karena mayoritas isi repo adalah TypeScript. p/owasp-top-ten, karena kerentanan Juice Shop mayoritas masuk kategori Top 10. Keduanya digabung dalam satu scan.
- Catatan: p/owasp-top-ten multi-bahasa, bukan khusus TypeScript. Karena itu ada temuan di YAML GitHub Actions, Terraform, dan .npmrc.
- Command: dijalankan dua kali, sekali dengan --json (reports/raw/semgrep.json) dan sekali dengan --sarif (reports/raw/semgrep.sarif). Lebih efisien satu run dengan --json-output=FILE dan --sarif-output=FILE.
- Exit code: 0, walaupun ada 43 temuan. Default Semgrep tidak gagal saat ada temuan. Untuk exit 1 saat ada temuan, pakai --error. Ini penting untuk gate di Fase 3.
- Field extra.lines berisi "requires login" karena tidak login ke Semgrep. Kode harus dibuka sendiri di path:line. Efek baiknya, raw report tidak menyalin potongan kode atau secret.

Cara triage: hitung dan kelompokkan dulu per severity, rule, dan folder, jangan dibaca satu per satu dari atas.

Total: 43 temuan dan 54 errors. Errors adalah file yang gagal dianalisis, bukan temuan.

| Severity | Jumlah |
|---|---|
| WARNING | 28 |
| ERROR | 13 |
| MEDIUM | 2 |

MEDIUM berasal dari rule supply chain (npm-missing-minimum-release-age) yang memakai skala berbeda dari ERROR/WARNING.

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

| Folder | Jumlah |
|---|---|
| .github | 13 |
| data | 10 |
| routes | 8 |
| (root) | 6 |
| terraform | 2 |
| infrastructure | 2 |
| lib | 1 |
| frontend | 1 |

Klasifikasi per path (produksi atau bukan):

| Kelas | Jumlah | Path |
|---|---|---|
| PROD-SERVER | 14 | routes/ (8 file), server.ts (5), lib/insecurity.ts (1) |
| NON-PROD: coding-challenge snippet | 10 | data/static/codefixes/ |
| INFRA/CONFIG | 19 | .github/workflows/ (13), terraform/ dan infrastructure/terraform/ (4), .npmrc dan frontend/.npmrc (2) |

Koreksi dari klasifikasi otomatis: frontend/.npmrc awalnya masuk PROD-CLIENT karena regex mencocokkan folder frontend/ duluan. File itu konfigurasi npm, bukan kode yang jalan di browser, jadi masuk INFRA/CONFIG. Pelajarannya, klasifikasi sebaiknya cek jenis file dulu, baru folder.

Catatan INFRA/CONFIG:
- Bukan produksi tidak berarti tidak penting. run-shell-injection di workflow CI bisa dipakai untuk mencuri secret atau GITHUB_TOKEN, jadi risikonya tetap nyata (supply chain).
- File Terraform berasal dari challenge "Vulnerable Infrastructure" (commit 458c66e82), jadi sengaja ditanam.

#### Triage: routes/search.ts:23

Rule: express-sequelize-injection (subcategory vuln, severity ERROR, CWE-89, likelihood/impact/confidence HIGH). Flow dilacak dengan --dataflow-traces.

| Langkah | Line | Kode | Peran |
|---|---|---|---|
| Source | 21 | criteria = req.query.q | input user dari query string; criteria hanya variabel pembawa taint |
| Transformasi | 22 | criteria.substring(0, 200) | hanya memotong panjang, bukan sanitizer |
| Sink | 23 | models.sequelize.query("... LIKE '%${criteria}%' ...") | criteria disisipkan langsung ke string SQL |

Verdict: true positive. criteria masuk ke perintah SQL tanpa parameterisasi (replacements/bind) dan tanpa dibersihkan. Pembatasan 200 karakter tidak mencegah SQLi karena payload UNION muat di bawah 200 karakter.

Catatan: marker vuln-code-snippet memang menandai challenge, tapi verdict harus berdiri di atas flow. Repo nyata tidak punya marker.

#### Keputusan noise: data/static/codefixes/

Pilihan: .semgrepignore.

| Cara | Kelebihan | Kekurangan |
|---|---|---|
| .semgrepignore | tersimpan di repo, konsisten di lokal dan CI | siapa pun yang bisa commit bisa menyembunyikan kode dari scanner, jadi perubahannya harus di-review; membuat file ini menimpa pola ignore default Semgrep |
| --exclude | cepat untuk eksperimen | hidup di command line, kalau lupa ditulis maka hasil berbeda |
| nosemgrep | presisi per baris, alasan bisa ditulis di komentar | harus ditulis di setiap baris temuan, tidak cocok untuk satu folder penuh |

#### Errors (54)

Errors adalah kegagalan Semgrep sendiri saat scan, bukan temuan. Semuanya level warn, artinya scan tetap jalan. Tapi tiap error adalah blind spot: bagian kode yang tidak dianalisis, jadi coverage tidak 100%.

| Jenis | Jumlah | Lokasi | Penilaian |
|---|---|---|---|
| PartialParsing | 35 | workflow .github, codefixes, dan file produksi frontend (payment, wallet, deluxe-user, dll.) | sebagian file dilewati; yang di frontend produksi perlu diwaspadai |
| Syntax error | 16 | data/static/codefixes/ | wajar, snippet memang tidak lengkap |
| Timeout | 3 | frontend/src/assets/private/three.js | wajar, library vendor besar |

#### S5: false negative dan batas SAST

Cara mencari: marker vuln-code-snippet start dipakai sebagai ground truth (lokasi bug yang pasti ada), lalu dibandingkan dengan path di report Semgrep (comm -23). Hasilnya 5 file yang punya bug tapi tidak ditemukan Semgrep:
- frontend/src/app/app.routing.ts
- frontend/src/app/search-result/search-result.component.ts
- lib/codingChallenges.ts
- routes/chat.ts
- routes/updateProductReviews.ts

Hipotesis awal "gagal parsing" dicek dengan data dan ternyata salah: kelima file ada di paths.scanned dan tidak ada di errors. Semgrep membaca kodenya, tapi tidak ada rule yang cocok. Ini false negative murni.

Bug 1: frontend/src/app/app.routing.ts (tokenSaleChallenge)
- Route rahasia disembunyikan dengan obfuscation (token1, token2) di kode frontend.
- Tidak ada source dan sink, jadi rule taint tidak punya pegangan.
- Kode frontend dikirim ke browser, jadi siapa pun bisa membaca dan men-decode-nya.
- Jenis: security through obscurity (CWE-656). Ini cacat desain, bukan pola kode, sehingga SAST berbasis pola tidak bisa melihatnya.

Bug 2: routes/updateProductReviews.ts (forgedReviewChallenge)
- Line 16 mengambil user yang sedang login, tapi nilai user tidak dipakai untuk membatasi review mana yang boleh diubah. Update hanya difilter dengan _id dari req.body.id.
- Akibatnya user bisa mengubah review milik orang lain: IDOR / broken access control.
- Kenapa Semgrep tidak menangkap: database-nya MarsDB (mirip MongoDB). Semua rule injection yang muncul di report sink-nya Sequelize. Tidak ada rule untuk sink MarsDB, dan cek kepemilikan data adalah logika bisnis yang tidak punya pola kode tetap.

Bug 3: routes/updateProductReviews.ts (noSqlReviewsChallenge)
- Source req.body.id, sink db.reviewsCollection.update(...) dengan multi: true.
- Body {"id": {"$ne": -1}, "message": "hacked"} membuat query { _id: { $ne: -1 } }. Di MongoDB/MarsDB key yang diawali $ adalah operator. $ne artinya not equal, sehingga query berarti cari review yang id-nya bukan -1, dan itu berarti semua review cocok. Ini kerentanan NoSQL injection yang mengubah struktur dan logika query. multi: true membuat database mengubah semua dokumen yang cocok, bukan hanya yang pertama, sehingga semua message jadi hacked.
- Bedanya dengan SQLi: operator diselipkan lewat struktur data (object JSON), bukan lewat tanda kutip.
- Perbaikan: wajibkan typeof req.body.id === 'string' atau tolak key yang diawali $, lalu tambahkan author: user.data.email ke filter. Kondisi author sekaligus menutup IDOR di Bug 2.
- Uji coba PoC (2026-11-14): PATCH /rest/products/reviews dengan body {"$ne": -1} menghasilkan {"modified":0}. Gagal karena operator dikirim di level atas, bukan sebagai nilai id, sehingga req.body.id kosong dan tidak ada review yang cocok. Body yang benar: {"id": {"$ne": -1}, "message": "hacked"}.

### SAST vs DAST

SAST (static, membaca kode secara whitebox):
- Melihat kode yang tidak terjangkau lewat UI, misalnya handler di routes/ yang tidak terhubung ke UI sehingga crawler tidak menemukannya.
- Memberi lokasi bug langsung (file dan baris), sedangkan DAST hanya memberi URL.
- Melihat secret dan kriptografi di source.
- Melihat infrastruktur sebagai kode, misalnya Terraform.

DAST (dynamic, menguji app yang sedang jalan seperti penetration testing):
- Melihat header HTTP, karena nilainya baru ada saat app jalan.
- Melihat atribut cookie di respons nyata.
- Melihat pesan error dan stack trace yang muncul saat runtime.
- Melihat efek konfigurasi reverse proxy atau WAF dan perilaku antar komponen.

Poin terpenting:
- DAST membuktikan bahwa bug benar-benar bisa dieksploitasi, jadi false positive-nya lebih sedikit.
- SAST lebih banyak false positive, tapi berjalan lebih awal, sebelum app di-deploy.
- Karena itu keduanya saling melengkapi, dan pipeline ini memakai keduanya.

### Status Semgrep

Selesai pada 2026-11-14 (scope ringkas).

Dibawa ke fase berikutnya:
- Buat .semgrepignore untuk data/static/codefixes/ (baru keputusan, file belum dibuat). Salin dulu pola ignore default Semgrep.
- Gate Fase 3: Semgrep perlu --error agar exit 1 saat ada temuan.
- Satu run untuk dua format: --json-output=FILE dan --sarif-output=FILE.
- Opsional: ulangi PoC NoSQL dengan body yang benar.
- routes/login.ts:34 tidak di-triage (scope ringkas). Polanya sama dengan search.ts.

### Langkah 3: Trivy

- Versi: Trivy 0.76.2, vulnerability DB versi 2 (UpdatedAt 2026-11-20). Detail dicatat di reports/raw/trivy-version.txt. DB diunduh ulang tiap hari, jadi hasil scan bisa berubah walaupun kode tidak berubah.
- Peran: SCA (Software Composition Analysis). Semgrep mencari bug di kode sendiri. Trivy mencari CVE di kode orang lain yang dipakai: dependency npm dan paket OS di image.

Command akhir:
- trivy fs --scanners vuln,secret,misconfig --include-dev-deps --skip-dirs reports --format json --output reports/raw/trivy-fs.json .
- trivy image --scanners vuln,secret,misconfig --image-config-scanners misconfig,secret --format json --output reports/raw/trivy-image.json juice-shop-local:latest

Scanner default adalah vuln,secret. misconfig ditambahkan karena berguna untuk Dockerfile dan Terraform. license dan --list-all-pkgs dibuang: license adalah urusan compliance, bukan security, dan --list-all-pkgs hanya perlu untuk SBOM.

Kesalahan di scan pertama:
- trivy fs tidak menemukan CVE npm sama sekali. Log hanya menulis INFO "Number of language-specific files num=0". Repo tidak punya package-lock.json (.npmrc berisi package-lock=false) dan tidak punya node_modules. Untuk Node, Trivy fs butuh lock file karena package.json hanya berisi range versi. Pelajarannya: scan bersih dengan exit 0 belum tentu aman, bisa jadi tool-nya buta.
- Perbaikan: lock file dibuat untuk root dan frontend dengan npm install --package-lock-only.
- Trivy memindai report-nya sendiri: reports/raw/gitleaks.json menghasilkan 108 secret, karena report gitleaks mentah berisi secret tanpa redaksi. Perbaikan: --skip-dirs reports. Ini juga bukti bahwa reports/raw/ wajib ada di .gitignore.

Lock file:
- Lock file berfungsi agar versi dependency di semua mesin sama. Di proyek nyata lock file di-commit.
- Di proyek ini lock file tidak di-commit, karena upstream sengaja memakai package-lock=false dan lock file ini hanya alat scan.
- Akibatnya ada drift: image di-build tanpa lock file, sehingga versi dipilih saat build, sedangkan lock file memilih versi tanggal 2026-11-20.
- --ignore-scripts penting saat menjalankan npm pada kode yang belum dipercaya. Script preinstall/postinstall menjalankan kode apa saja dengan hak akses user, misalnya membaca ~/.ssh atau token di env, sehingga bisa menjadi serangan supply chain.

Exit code: default selalu 0 walaupun ada temuan. Trivy keluar 1 kalau error. Kalau --exit-code 1 dipakai untuk temuan, gate tidak bisa membedakan "ada CVE" dan "Trivy crash" (masalah yang sama dengan gitleaks). Untuk Fase 3: pakai --exit-code 2 dan --severity HIGH,CRITICAL.

T2: jumlah temuan vuln

| Severity | fs | image |
|---|---|---|
| CRITICAL | 9 | 9 |
| HIGH | 29 | 28 |
| MEDIUM | 30 | 81 |
| LOW | 4 | 16 |
| UNKNOWN | 0 | 4 |

FixedVersion adalah versi paling rendah yang sudah menambal kerentanan. Tidak semua temuan punya.
- fs: 64 ada fix, 8 tanpa fix.
- image: 65 ada fix, 73 tanpa fix. 66 dari 68 temuan paket OS Debian tidak punya fix (Status affected): Debian belum merilis patch, jadi upgrade npm tidak menolong. Pilihannya menunggu, ganti base image, atau terima risiko.

T3: kenapa fs dan image berbeda
Keduanya memindai benda yang berbeda. fs memindai repo di folder. image memindai hasil build yang benar-benar dirilis ke produksi.
- Hanya di fs: devDependencies (--omit=dev membuangnya dari image) dan misconfig Dockerfile.
- Hanya di image: paket OS dari base image distroless (kelas os-pkgs) dan misconfig metadata image (USER, HEALTHCHECK).
- Versi package bisa berbeda karena drift lock file.
- File test dan Terraform ikut masuk image karena tidak dikecualikan di .dockerignore. .dockerignore hanya mengecualikan terraform/ dan test/ di root, tapi infrastructure/terraform/, data/static/codefixes/, dan frontend/src/**/*.spec.ts tetap ikut. Stage installer menjalankan COPY . /juice-shop, lalu stage akhir menyalin seluruh /juice-shop.

T4: bedah crypto-js (CVE-2023-46233)

| Pertanyaan | Jawaban |
|---|---|
| Package | crypto-js 3.3.0, CRITICAL, CVSS 9.1, CWE-916/327/328 |
| Isi CVE | PBKDF2 default memakai SHA1 dan 1 iterasi, jauh lebih lemah dari standar |
| Direct atau transitive | transitive. Tidak ada di package.json Juice Shop; induknya pdfkit 0.11.0 (dicek dari package-lock.json lalu package.json pdfkit di image) |
| Installed ke fixed | 3.3.0 ke 4.2.0. Status fixed artinya upstream sudah merilis patch, bukan berarti versi terpasang aman |
| Reachable | tidak. pdfkit memakai crypto-js untuk MD5 (generateFileID, selalu dipanggil), RC4, AES, dan SHA256 (enkripsi PDF), tapi tidak memakai PBKDF2. Juice Shop memakai pdfkit di routes/order.ts tanpa enkripsi |
| Prioritas | rendah. Tetap temuan dan tetap perlu di-upgrade lewat pdfkit, tapi fungsi rentan tidak terjangkau |

Pelajaran dari T4: dua kesalahan cek awal. Status fixed salah dibaca sebagai aman. grep "crypto-js|CryptoJS|PBKDF2" tanpa -E membaca | sebagai karakter biasa, jadi hasil kosong tidak berarti apa-apa. Cek reachability harus di kode (js/pdfkit.js), bukan di package.json.

T5: blind spot Trivy
- Bug di kode sendiri (bagian Semgrep).
- Perilaku saat runtime (bagian ZAP).
- Reachability: apakah fungsi rentan benar-benar dipakai.
- Dependency yang tidak tercatat di lock file.
- Kode vendor tanpa package.json, misalnya frontend/src/assets/private/three.js. Trivy tidak tahu versinya.
- Dependency frontend di image sudah di-bundle menjadi JS hasil build, tanpa package.json. Trivy image buta terhadap CVE frontend; hanya trivy fs dengan lock file yang melihatnya. Karena itu keduanya dijalankan.

### Status Trivy

Selesai pada 2026-11-20 (scope ringkas).

Dibawa ke fase berikutnya:
- Gate Fase 3: --exit-code 2 dan --severity HIGH,CRITICAL; pertimbangkan --ignore-unfixed untuk paket OS tanpa patch.
- CI butuh lock file untuk trivy fs, atau scan image sebagai sumber SCA backend.
- Perketat .dockerignore (infrastructure/, data/static/codefixes/, file spec) agar image tidak membawa file non-produksi.

### Langkah 4: ZAP

- Image: ghcr.io/zaproxy/zaproxy:stable (image lama owasp/zap2docker-* sudah deprecated).
- Peran: DAST. ZAP menguji app yang sedang berjalan dari luar lewat HTTP, tanpa membaca kode.

Z1: baseline itu pasif atau aktif
Pasif, tidak ada payload berbahaya ke target menurut dokumentasi. Spider default 1 menit, bisa diubah dengan -m <menit>. Catatan: pasif bukan berarti tanpa traffic. Spider tetap crawl semua link dan bisa submit form, jadi endpoint GET yang mengubah state (misalnya /logout atau /delete?id=1) tetap bisa terpicu. Yang pasif adalah analisisnya: ZAP hanya membaca response yang lewat.

Z2: kenapa full scan tidak boleh ke target yang bukan milik sendiri
Full scan menjalankan active scan dan mengirim payload berbahaya seperti SQLi dan XSS. Itu bisa merusak data dan dianggap serangan nyata. Tanpa izin tertulis (scope/RoE) termasuk akses ilegal (UU ITE Pasal 30 dan 33). Active scan juga mengirim ribuan request dan bisa membuat target lambat atau down, jadi full scan ke sistem sendiri pun diarahkan ke staging, bukan production.

Flag baseline:

| Flag | Fungsi |
|---|---|
| -t | target |
| -r | report HTML |
| -J | report JSON, yang dipakai untuk parsing |
| -I | WARN tidak menghasilkan exit 2. Hanya mengubah exit code, isi report tetap berisi WARN |
| -m | durasi spider dalam menit |
| -g / -c | -g membuat file config rule, -c memakai config itu untuk set tiap rule ke IGNORE/WARN/FAIL. Ini cara tuning noise di ZAP |

Exit code (dicek dari source /zap/zap-baseline.py di image): 1 kalau ada FAIL, 2 kalau ada WARN dan tidak memakai -I, 0 kalau hanya PASS, 3 kalau error lain. Scan pertama dilaporkan exit 0 padahal ada 7 WARN tanpa -I, jadi itu salah ukur. Gate yang salah membaca exit code akan selalu lolos. Jangan pakai -I di gate Fase 3 tanpa alasan jelas.

Jaringan: container ZAP tidak bisa memakai 127.0.0.1 untuk menjangkau app, karena 127.0.0.1 di dalam container adalah container itu sendiri.
- Jalur A, --network host: ZAP berbagi network namespace dengan host. Semua service di 127.0.0.1 host bisa dijangkau, dan port ZAP sendiri terbuka di host. Paling mudah, isolasi paling lemah. Action resmi zaproxy/action-baseline di GitHub Actions memakai jalur ini.
- Jalur B, user-defined network: ZAP dan juice di satu network, target memakai nama container (http://juice:3000). Dipilih karena isolasi.

Z3: apa yang bisa dijangkau ZAP di network biasa (zapnet)
Bukan hanya Juice Shop. Semua port semua container di network itu, host lewat gateway (172.20.0.1, dan host punya listener di 0.0.0.0:80), serta internet karena internal=false. docker network connect menambah network, tidak memindahkan: juice waktu itu terhubung ke bridge dan zapnet sekaligus.

Z3b: cara menutupnya
docker network create --internal zapnet-int. Container di network internal hanya bisa bicara dengan sesama container di network itu, tidak bisa keluar ke internet. Port publish (-p) tidak berfungsi untuk container yang hanya terhubung ke network internal. Trade-off: browser di host tidak bisa membuka Juice Shop lagi, jadi verifikasi manual dilakukan dari container di network yang sama.

Isolasi hanya berlaku kalau semua network non-internal dilepas. Selama juice masih terhubung ke bridge atau zapnet, juice tetap punya jalan keluar dan -p tetap aktif.

Verifikasi Z3b (Docker 29.1.3):
- 6a, -p diabaikan: container uji dengan -p 127.0.0.1:3001:3000 di zapnet-int. Kolom Ports hanya 3000/tcp tanpa panah (hanya EXPOSE dari Dockerfile, bukan port terbuka di host), curl ke 127.0.0.1:3001 gagal. -p diterima tanpa error tapi diam-diam diabaikan. Konfigurasi keamanan yang terlihat benar belum tentu aktif, selalu verifikasi.
- 6b, tidak ada internet, diblok di dua lapis:
  - DNS: curl https://google.com gagal dengan exit 6 (Could not resolve host). DNS internal Docker tidak meneruskan nama luar.
  - Routing: curl https://1.1.1.1 (IP langsung, tanpa DNS) gagal dengan exit 7 setelah 0 ms. Gagal seketika artinya tidak ada route keluar, paket tidak pernah dikirim.
  - docker run meneruskan exit code proses di dalam container, jadi echo $? setelah docker run menghasilkan 6, sama dengan exit code curl.
- 6c, antar container jalan: curl ke http://juice:3000 dari container di zapnet-int menghasilkan 200 OK. Nama juice di-resolve oleh DNS internal Docker.
- 6d, host tidak bisa dijangkau: curl http://172.21.0.1:80 gagal dengan exit 28 (timeout setelah 5 detik). Timeout artinya paket dikirim tapi dibuang diam-diam oleh firewall (DROP). Percobaan pertama memakai 127.21.0.1 karena typo; itu loopback milik container ZAP sendiri, jadi tidak membuktikan apa pun.
- Cara membaca error curl: gagal seketika tanpa balasan (exit 7, 0 ms) berarti tidak ada route. Timeout (exit 28) berarti paket dikirim tapi dibuang di tengah jalan. Connection refused (juga exit 7, tapi pesannya berbeda) berarti paket sampai tapi tidak ada yang listen di port itu. Exit 7 bisa berarti dua hal, jadi baca pesannya, bukan hanya angkanya.
- Klaim di Z3 bahwa zapnet bisa menjangkau host:80 lewat gateway adalah kesimpulan dari konfigurasi (internal=false dan listener 0.0.0.0:80), belum diuji langsung karena zapnet sudah dihapus.

Insiden: container juice hilang di tengah langkah. Container lama yang dijalankan tanpa -d di terminal lain dimatikan dengan Ctrl+C. docker events mencatat kill sig=28 (SIGWINCH, ukuran terminal berubah), kill sig=2 (SIGINT, Ctrl+C), die exit=0, lalu destroy karena --rm. Pelajaran: Ctrl+C di terminal yang ter-attach mematikan container (lepas tanpa mematikan: Ctrl+P lalu Ctrl+Q), docker logs -f aman untuk melihat log, dan --rm ikut menghapus konfigurasi network dan log. Pemulihan cukup satu command: docker run --rm -d --name juice --network zapnet-int juice-shop-local.

Scan baseline (langkah 7):
- Command: docker run --rm -t --network zapnet-int -v "$(pwd)/reports/raw:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://juice:3000 -J zap-baseline.json -r zap-baseline.html
- Hasil: FAIL-NEW 0, WARN-NEW 7, PASS 61. Exit code 2, sesuai logika source (ada WARN, tanpa -I).
- File di reports/raw: zap-baseline.json, zap-baseline.html, dan zap.yaml. zap.yaml adalah plan Automation Framework yang dibuat otomatis oleh zap-baseline.py (job: passiveScan-config, spider 1 menit, passiveScan-wait, outputSummary, dua job report).
- Console hanya menampilkan maksimal 5 URL per rule walaupun count lebih besar (misalnya 10049 x 6, 90004 x 10). Daftar lengkap ada di report.
- Report JSON hanya berisi 3 alert (10038, 10098, 10109), padahal daftar 7 WARN berasal dari scan pertama di zapnet yang masih punya internet. Penyebabnya ada di bagian Akar masalah di bawah. Exit code dihitung dari summary file internal (/home/zap/zap_out.json), bukan dari report JSON. Artinya gate yang membaca report JSON bisa melihat hasil yang berbeda dari exit code.
- Insights di JSON: 77 error dan 3 warning tercatat di zap.log, 45 network failure. zap.log ada di dalam container dan hilang karena --rm.

Akar masalah: 4 rule hilang di network internal
- zap-baseline.py baris 434-439: kalau tidak memakai -silent, ZAP dijalankan dengan -addonupdate -addoninstall pscanrulesBeta. Komentarnya: "In case we're running in the stable container". Image stable hanya membawa pscanrules-release dan pscan-alpha, tidak membawa pscanrulesBeta.
- Di zapnet-int tidak ada internet, jadi install gagal. Satu-satunya jejak di zap.log adalah "ERROR CommandLine - Check for updates call failed". Daftar rule yang di-load tidak berisi rule beta sama sekali.
- Rule yang hilang semuanya beta: 10049 Storable and Cacheable Content, 10063 Permissions Policy, 10110 Dangerous JS Functions, 90004 Insufficient Site Isolation.
- Scan tetap selesai dengan exit 2 dan tanpa error di console. Coverage turun diam-diam.
- Semua 86 ERROR di zap.log adalah call home yang gagal (cfu.zaproxy.org untuk check for updates, tel.zaproxy.org untuk telemetry). Ini juga bukti isolasi bekerja: ZAP tidak bisa mengirim telemetry keluar.
- Pelajaran: isolasi dan coverage saling tarik. Hardening jaringan bisa mematikan sebagian scanner tanpa ada tanda gagal. Hitung jumlah rule yang di-load, jangan hanya melihat exit code.
- zap.log disimpan dengan menjalankan container tanpa --rm, lalu docker cp zapscan:/home/zap/.ZAP/zap.log reports/raw/, lalu docker rm zapscan.

Z4: pengelompokan 7 WARN (dari scan dengan internet)

| Kelompok | Rule | Risk (confidence) | Catatan |
|---|---|---|---|
| Kerentanan nyata (masih kemungkinan) | 10098 Cross-Domain Misconfiguration | Medium (Medium) | dipicu Access-Control-Allow-Origin: * yang terlihat di 6c. Dibedah di Z5 |
| Hardening header | 10038 CSP Header Not Set | Medium (High) | lapisan pertahanan tambahan terhadap XSS, bukan celah yang bisa dieksploitasi sendiri |
| Hardening header | 10063 Deprecated Feature Policy Header Set | Low, beta | rule ini juga memberi alert kalau Permissions-Policy tidak ada. Di sini yang terpicu varian header Feature-Policy yang deprecated (terlihat di 6c) |
| Hardening header | 90004 Insufficient Site Isolation (Spectre) | Low, beta | varian COEP missing. Ada tiga varian: CORP, COEP, COOP |
| Informational | 10109 Modern Web Application | Informational (Medium) | penanda app adalah SPA, jadi spider klasik kemungkinan tidak melihat semua route. Ini soal coverage scan |
| Informational | 10049 Storable and Cacheable Content | Informational, beta | Cache-Control: public, max-age=0 |
| Petunjuk kerentanan nyata | 10110 Dangerous JS Functions | Low, beta | hanya mencocokkan pola fungsi di response, tapi pola yang cocok adalah penyebab XSS. Lihat bagian 10110 di bawah |

Directory listing /ftp tidak dilaporkan karena Directory Browsing (ID 0) adalah rule active scan. Baseline hanya menjalankan rule pasif.

Z4b: cara mendapatkan rule beta tanpa membuka internet
- A, kembali ke network non-internal: Juice Shop yang sengaja rentan bisa keluar lagi, dan salah ketik -t bisa mengenai situs asli. Jalan tengah: ZAP terhubung ke dua network (zapnet-int dan network biasa), Juice Shop tetap hanya di zapnet-int. Juice Shop tetap terisolasi, tapi ZAP sendiri bisa ke internet dan ke host.
- B, image sendiri FROM ghcr.io/zaproxy/zaproxy:stable dengan pscanrulesBeta di-install saat build, lalu scan dengan -z "-silent": paling mirip pipeline asli. Rule diunduh saat build, bukan saat run, sehingga versi rule terkunci dan hasil scan bisa diulang. Kekurangannya image harus di-build ulang secara berkala untuk mendapat rule baru. -silent tetap perlu agar ZAP tidak mencoba update saat run.
- C, terima tanpa rule beta: tidak oke, karena rule-nya ada dan bisa dijalankan, hanya tidak terunduh. Ini bukan blind spot tool, tapi celah konfigurasi.
- Catatan supply chain: perilaku default mengunduh add-on versi terbaru di setiap run. Hasil scan bisa berubah tanpa ada perubahan kode, dan kalau server add-on disusupi, kode itu langsung jalan di scanner.
- Keputusan: B, dikerjakan saat ZAP masuk CI. Untuk Fase 1, daftar 7 WARN dari scan dengan internet sudah cukup.

10110 Dangerous JS Functions: bukan noise
- main.js berisi 10 panggilan bypassSecurityTrust (8 bypassSecurityTrustHtml, 2 bypassSecurityTrustUrl). Fungsi Angular ini mematikan sanitizer bawaan, jadi HTML ditampilkan apa adanya.
- Sumbernya 9 baris di frontend/src/app (grep tanpa file spec). Dua di antaranya ditandai Juice Shop sebagai baris rentan: search-result.component.ts:146 (localXssChallenge, isi parameter search dari URL langsung dirender) dan search-result.component.ts:113 (restfulXssChallenge, deskripsi produk dari API).
- ZAP hanya melihat pola, tidak tahu data mana yang dikendalikan penyerang. Contoh: queryParam di search berasal dari URL (berbahaya), sedangkan captcha di data-export berasal dari server. Untuk membedakannya perlu baca kode (source ke sink).
- Semgrep (ruleset yang dipakai di Langkah 2) tidak melaporkan satu pun dari 9 baris itu. Rule beta ZAP menemukan petunjuk yang terlewat oleh SAST.
- grep di zap-baseline.html kosong karena report itu berasal dari scan offline yang tidak menjalankan rule beta.

Stack trace di /ftp/encrypt.pyc (403)
- URL aneh /juice-shop/node_modules/express/lib/router/index.js:286:9 di hasil spider bukan file asli. Itu satu frame stack trace (file, baris 286, kolom 9) di halaman error 403. Spider membaca teks path itu sebagai link.
- Yang bocor dari halaman error:
  - Nama aplikasi OWASP Juice Shop dan framework Express ^4.22.1. Tanda ^ berarti range dari package.json, bukan versi yang terpasang.
  - Runtime Node.js, terlihat dari frame node:fs.
  - Aturan filter: hanya .md dan .pdf yang boleh diunduh.
  - Path absolut instalasi (/juice-shop/) dan struktur folder hasil build (build/routes/fileServer.js).
  - Lokasi persis pengecekan filter: fungsi verify di fileServer.js baris 68. Penyerang tahu filter mana yang harus di-bypass dan bisa membaca logikanya di source yang terbuka.
  - Middleware serve-index, yaitu modul yang membuat directory listing /ftp.
- ZAP tidak melaporkannya walaupun rule Application Error Disclosure (90022) dan Information Disclosure - Debug Error Messages (10023) ter-load. Pola deteksinya ada di pscanrules-release-77.zap (xml/application_errors.xml dan xml/debug-error-messages.txt). Isinya pola PHP, ASP.NET, Java, IIS, dan pesan error database. Tidak ada pola untuk stack trace Node.js atau Express.
- Pelajaran: rule berbasis signature hanya menemukan pola yang sudah ditulis. ZAP bahkan meng-crawl path dari stack trace itu, tapi tidak mengenalinya sebagai kebocoran. Blind spot ini harus ditutup dengan review manual atau rule tambahan.

Z5: bedah 10098 Cross-Domain Misconfiguration

| Pertanyaan | Jawaban |
|---|---|
| Pemicu | header Access-Control-Allow-Origin: * di semua response. Sumbernya server.ts:183-184, app.options('*', cors()) dan app.use(cors()) tanpa opsi, jadi default origin * |
| Arti header | website mana pun boleh membaca response Juice Shop lewat JavaScript, selama request dikirim tanpa kredensial |
| Cara login frontend | token disimpan di dua tempat: localStorage (login.component.ts:110) dan cookie token (login.component.ts:113). request.interceptor.ts:16 mengirim Authorization: Bearer dari localStorage di setiap request |
| Cara backend membaca token | campuran. isAuthorized (lib/insecurity.ts:52) memakai expressJwt tanpa getToken kustom, jadi hanya membaca header Authorization. Beberapa route membaca cookie: currentUser.ts, dataErasure.ts, profileImageFileUpload.ts, profileImageUrlUpload.ts, updateUserProfile.ts, userProfile.ts. insecurity.ts:187 memprioritaskan cookie, header hanya cadangan |
| Bisa curi data user yang login? | tidak lewat ACAO * saja |
| Prioritas | rendah untuk Juice Shop yang memang publik. Naik kalau app yang sama berjalan di jaringan internal |

Kenapa ACAO * saja tidak cukup untuk mencuri sesi:
- Route yang memakai header: website jahat tidak punya token korban. localStorage terikat ke origin, jadi JavaScript di domain lain tidak bisa membacanya, dan browser tidak menambahkan header Authorization secara otomatis.
- Route yang memakai cookie: browser hanya mengirim cookie kalau request memakai credentials: 'include'. Untuk request seperti itu, aturan CORS melarang JavaScript membaca response kalau header-nya ACAO: *. Origin harus ditulis persis dan Access-Control-Allow-Credentials: true harus ada.
- CORS hanya memblok pembacaan response, bukan pengiriman request. Route berbasis cookie tetap bisa menerima request dari situs lain (CSRF), tapi itu masalah terpisah yang tidak disebabkan oleh ACAO *.

Risiko nyata ACAO *:
- Data yang bisa dibaca tanpa login bisa diambil website mana pun lewat browser pengunjungnya.
- Skenario jaringan internal: kalau app berjalan di intranet, website luar yang dibuka karyawan bisa membaca app internal lewat browser karyawan itu. Batas jaringan jadi tidak berarti.
- Konfigurasi yang benar-benar berbahaya adalah origin yang dipantulkan dari header Origin request, ditambah Allow-Credentials: true.

Pelajaran: rating Medium dari ZAP adalah rating umum. Risiko sebenarnya tergantung cara app menyimpan login dan siapa yang bisa menjangkau app.

Z6: blind spot ZAP baseline
- 10109 Modern Web Application: spider klasik hanya membaca link di HTML dan tidak menjalankan JavaScript. Route Angular (#/...) dibuat oleh JavaScript di main.js, jadi tidak terlihat. Masalah utamanya bukan durasi 1 menit. Solusinya AJAX spider (-j) yang memakai browser headless.
- /ftp: directory listing tidak dilaporkan karena rule Directory Browsing (ID 0) adalah rule active, sedangkan baseline hanya menjalankan rule pasif.
- Stack trace: halaman 403 membocorkan framework Express, struktur direktori, dan aturan filter .md/.pdf. Rule error disclosure tidak punya pola untuk stack trace Node.js/Express, jadi tidak ada alert.
- 4 rule beta hilang karena ZAP di network internal tidak bisa mengunduh pscanrulesBeta. Ini celah konfigurasi, bukan batas tool, dan tidak terlihat dari exit code.
- ZAP melabeli 10098 sebagai Medium tanpa tahu model auth aplikasinya. Rating risiko ZAP tidak mengenal konteks.
- bypassSecurityTrustHtml: ZAP (rule beta 10110) melihat polanya, tapi tidak bisa membedakan mana yang datanya dikendalikan penyerang dan tidak membuktikan XSS. Baseline juga tidak mengirim payload untuk menguji.
- Tambahan:
  - Scan tanpa login. Semua yang ada di balik login (basket, profil, halaman admin) tidak diuji.
  - Hanya pasif. Injeksi seperti SQLi di routes/search.ts yang ditemukan Semgrep tidak bisa ditemukan baseline.
  - Endpoint API yang tidak di-link dari HTML (/rest/..., /api/...) tidak ditemukan spider. Perlu definisi OpenAPI dan zap-api-scan.py.
  - Logika bisnis (misalnya jumlah negatif di basket atau saldo wallet) tidak bisa dideteksi tool mana pun.
  - Jumlah instance tidak akurat. zap.log mencatat "Disabling passive scan rule ... as it has raised more than 10 alerts" (maxAlertsPerRule 10), jadi count adalah batas bawah, bukan total.

### Status ZAP

Selesai pada 2026-11-21 (scope ringkas).

Dibawa ke fase berikutnya:
- Image ZAP sendiri dengan pscanrulesBeta di-install saat build, scan dengan -z "-silent" (keputusan Z4b B).
- Gate Fase 3: exit 1 untuk FAIL, 2 untuk WARN, 3 untuk error. Tuning rule IGNORE/WARN/FAIL lewat -g dan -c. Jangan pakai -I tanpa alasan.
- Script Fase 4: jangan hanya membaca report JSON. Cek juga jumlah rule yang di-load, karena coverage bisa turun tanpa error.
- Pertimbangkan AJAX spider (-j), scan dengan login, dan zap-api-scan.py.
- Pilihan jaringan di CI berbeda: runner GitHub Actions adalah VM sekali pakai yang punya internet.
