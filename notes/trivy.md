# Trivy

SCA (Software Composition Analysis). Semgrep mencari bug di kode sendiri, Trivy mencari CVE di kode orang lain yang dipakai: dependency npm dan paket OS di image.

- Versi 0.76.2, vulnerability DB versi 2 (UpdatedAt 2026-11-20), dicatat di reports/raw/trivy-version.txt.
- trivy fs --scanners vuln,secret,misconfig --include-dev-deps --skip-dirs reports --format json --output reports/raw/trivy-fs.json .
- trivy image --scanners vuln,secret,misconfig --image-config-scanners misconfig,secret --format json --output reports/raw/trivy-image.json juice-shop-local:latest
- Scanner default vuln,secret. misconfig kutambah untuk Dockerfile dan Terraform. license dan --list-all-pkgs kubuang: license urusan compliance, dan --list-all-pkgs hanya perlu untuk SBOM.

## Cara kerja

1. Inventaris. Trivy membaca file metadata, bukan kode. Distro dikenali dari /etc/os-release. Paket OS dibaca dari database dpkg (di distroless ada di /var/lib/dpkg/status.d/). Paket npm dibaca dari lock file, atau dari package.json di setiap folder node_modules di dalam image.
2. Pencocokan. Setiap paket dicari di trivy-db, yang dirakit dari advisory vendor distro, GHSA, NVD, dan sumber lain. Versi terpasang dibandingkan dengan range versi rentan memakai aturan versi ekosistemnya (format versi Debian beda dengan semver npm).
3. Untuk paket OS, Trivy memakai advisory distro, bukan range versi upstream. Karena itu patch backport Debian tetap dikenali.
4. Output: ID CVE, versi terpasang, versi fix, status, dan severity (vendor didahulukan).

Trivy tidak tahu kenapa sesuatu jadi masalah. Penjelasannya ditulis manusia di advisory, Trivy cuma mencocokkan. Ibaratnya Trivy mencocokkan daftar bahan dengan daftar produk yang ditarik dari pasar, sedangkan Semgrep membaca resepnya. Akibatnya Trivy hanya menemukan kerentanan yang sudah dikenal, di versi yang sudah dikenal, dan tidak bisa menilai reachability.

Scanner lain di Trivy beda cara kerjanya. Scanner secret pakai regex seperti gitleaks. Scanner misconfig mengecek Dockerfile dan Terraform terhadap aturan kebijakan, lebih mirip Semgrep tapi untuk file konfigurasi.

## Apa yang ditemukan

| Severity | fs | image |
|---|---|---|
| CRITICAL | 9 | 9 |
| HIGH | 29 | 28 |
| MEDIUM | 30 | 81 |
| LOW | 4 | 16 |
| UNKNOWN | 0 | 4 |

- fs: 64 ada fix, 8 tanpa fix.
- image: 65 ada fix, 73 tanpa fix. 66 dari 68 temuan paket OS Debian berstatus affected, artinya Debian belum merilis patch. Upgrade npm tidak menolong. Pilihannya menunggu, ganti base image, atau terima risiko.
- FixedVersion adalah versi paling rendah yang sudah menambal. Status fixed artinya upstream sudah merilis patch, bukan berarti versi yang terpasang aman.

### Scan pertama buta
trivy fs pertama tidak menemukan CVE npm sama sekali dan exit 0. Log cuma menulis INFO "Number of language-specific files num=0". Repo tidak punya package-lock.json (.npmrc berisi package-lock=false) dan tidak punya node_modules. Untuk Node, Trivy fs butuh lock file karena package.json hanya berisi range versi. Lock file lalu kubuat dengan npm install --package-lock-only --ignore-scripts, hanya untuk scan dan tidak di-commit.

Trivy juga sempat memindai report-nya sendiri: reports/raw/gitleaks.json menghasilkan 108 secret karena report gitleaks mentah tidak di-redact. Solusinya --skip-dirs reports. Ini sekaligus bukti reports/raw/ wajib ada di .gitignore.

### Kenapa fs dan image berbeda
fs memindai repo di folder, image memindai hasil build yang dirilis.
- Hanya di fs: devDependencies (dibuang --omit=dev dari image) dan misconfig Dockerfile.
- Hanya di image: paket OS dari base image distroless dan misconfig metadata image (USER, HEALTHCHECK).
- Versi package bisa beda karena drift: image di-build tanpa lock file, jadi versinya dipilih saat build.
- File test dan Terraform ikut masuk image. .dockerignore hanya mengecualikan terraform/ dan test/ di root, sedangkan infrastructure/terraform/, data/static/codefixes/, dan file spec.ts di frontend tetap ikut.

## Cara menganalisa: bedah crypto-js (CVE-2023-46233)

| Pertanyaan | Jawaban |
|---|---|
| Package | crypto-js 3.3.0, CRITICAL, CVSS 9.1, CWE-916/327/328 |
| Isi CVE | PBKDF2 default memakai SHA1 dan 1 iterasi, jauh lebih lemah dari standar |
| Direct atau transitive | transitive. Tidak ada di package.json Juice Shop; induknya pdfkit 0.11.0 (dicek dari package-lock.json, lalu package.json pdfkit di image) |
| Installed ke fixed | 3.3.0 ke 4.2.0 |
| Reachable | tidak. pdfkit memakai crypto-js untuk MD5 (generateFileID, selalu dipanggil), RC4, AES, dan SHA256, tapi tidak PBKDF2. Juice Shop memakai pdfkit di routes/order.ts tanpa enkripsi |
| Prioritas | rendah. Tetap temuan dan tetap perlu di-upgrade lewat pdfkit, tapi fungsi rentannya tidak terjangkau |

Reachability dicek di kode library (js/pdfkit.js), bukan di package.json.

## Insight

### Severity bukan prioritas
- Severity bukan buatan Trivy. Nilainya dari NVD, advisory vendor distro, dan GHSA, biasanya CVSS base score: dampak terburuk tanpa konteks.
- Untuk paket OS, severity vendor distro didahulukan. Bisa beda jauh dari NVD, misalnya NVD bilang CRITICAL tapi Debian bilang LOW karena build Debian tidak memakai fitur yang rentan. Bandingkan di field VendorSeverity dan CVSS di report JSON.
- Prioritas itu severity ditambah konteks: fungsi rentan terjangkau atau tidak, paketnya dipakai saat runtime atau tidak, syarat serangan terpenuhi atau tidak, sudah ada exploit nyata atau tidak (EPSS, CISA KEV), dan sudah ada fix atau tidak.
- Latihan A/B: CVE HIGH yang masuk KEV, ada di endpoint publik, dan sudah punya fix dikerjakan lebih dulu daripada CVE CRITICAL yang tidak terjangkau dan belum punya fix. Severity A tetap CRITICAL, yang turun prioritasnya.

### Gate yang cuma lihat severity bisa terbalik
Dengan --severity CRITICAL, CVE A (CRITICAL, tidak terjangkau) menggagalkan build, sedangkan CVE B (HIGH, masuk KEV) lolos. Yang aman diblokir, yang berbahaya diloloskan.

Default exit code Trivy 0 walaupun ada temuan, dan 1 kalau error. Jadi pakai --severity HIGH,CRITICAL dengan --exit-code 2, supaya "ada CVE" dan "Trivy crash" bisa dibedakan (masalah yang sama dengan gitleaks). Trivy tidak bisa mengukur reachability sendiri, jadi reachability masuk ke gate lewat triage tim yang dicatat di .trivyignore atau VEX.

### Risk acceptance yang bisa diaudit
- Temuan yang risikonya diterima masuk .trivyignore, satu CVE per baris, dengan komentar alasan, bukti, dan pemilik, plus tanggal kedaluwarsa (exp:YYYY-MM-DD). Setelah lewat, temuan muncul lagi dan harus direview.
- Klaim tidak terjangkau harus ada buktinya, misalnya hasil grep pemakaian fungsi dan dependency tree.
- Review ulang lebih cepat kalau fix dirilis, EPSS naik, CVE masuk KEV, atau kode mulai memakai fungsi yang rentan.
- Kalau paketnya tidak dipakai sama sekali, lebih baik dibuang dari image daripada di-ignore.

Risiko --ignore-unfixed: semua temuan tanpa fix hilang sekaligus tanpa jejak (di image ini 66 temuan Debian). Padahal temuan tanpa fix bisa saja sudah dieksploitasi, dan itu butuh mitigasi (matikan fitur, buang paket, WAF), bukan disembunyikan. .trivyignore mengabaikan satu CVE dengan alasan, --ignore-unfixed menyaring satu kelas temuan tanpa melihat isinya.

### FP atau temuan benar
Pertanyaan pembedanya: kerentanannya benar-benar ada di image atau tidak?
- FP: scanner salah, kerentanannya tidak ada. Misalnya Debian sudah menambal lewat backport tapi Trivy masih mengira rentan. Diabaikan permanen dengan alasan.
- Temuan benar yang diterima: ada, tapi risikonya diterima (CVE A). Dicatat dengan alasan, bukti, dan exp.
- Temuan benar yang harus diperbaiki: ada dan berisiko (CVE B). Punya pemilik dan tenggat.

Kenapa penting dibedakan: label FP artinya diabaikan selamanya, jadi temuan benar yang dicap FP tersembunyi permanen. Catatan audit juga jadi salah. Angka FP mengukur kualitas tool, angka temuan benar mengukur utang keamanan aplikasi. Kalau dicampur, tim bisa mengira tool-nya berisik lalu mematikannya.

### Fix untuk transitive dependency
- npm install crypto-js@4.2.0 di root tidak menolong. npm memilih versi untuk pdfkit dari range di package.json milik pdfkit (3.x), jadi terpasang dua salinan: 4.2.0 di root dan 3.3.0 di dalam node_modules pdfkit. Trivy tetap menemukan 3.3.0.
- --force bukan solusi, cuma melewati pengecekan konflik. Mengedit package.json pdfkit di node_modules juga bukan, karena hilang setiap npm install.
- Urutan pilihan: upgrade pdfkit ke versi yang sudah pakai crypto-js 4.x, kalau belum ada pakai field overrides di package.json root (npm 8.3 ke atas, di yarn namanya resolutions) lalu buat ulang lock file, ganti library, atau terima risiko lewat .trivyignore.
- Risiko overrides: crypto-js 3 ke 4 lompatan major, jadi bisa ada breaking change yang diam. Setelah override, tes pembuatan PDF order di routes/order.ts karena pdfkit selalu memanggil MD5. Override tanpa scope berlaku untuk semua package. Override itu utang: catat alasannya dan hapus begitu pdfkit sudah update.

### Hasil bisa berubah tanpa kode berubah
Commit yang sama bisa hijau Senin dan merah Selasa, karena DB diperbarui, entri .trivyignore kedaluwarsa, atau vendor mengubah severity. Ini bagus, risikonya memang sudah ada sejak Senin. Tapi kalau PR sering gagal karena hal di luar kendali developer, muncul alert fatigue dan orang mulai cari cara bypass. Solusinya memisahkan posisi scan:
- Gate PR (blocking): hanya temuan yang dibawa PR itu sendiri. Trivy tidak punya baseline bawaan, jadi caranya membandingkan dengan hasil scan main. Di repo ini lock file tidak di-commit, jadi perubahan dependency di PR susah dilihat.
- Scan terjadwal (tidak blocking): cron harian untuk main dan image yang sedang jalan. CVE baru jadi issue dengan pemilik.
- Gate rilis (blocking): scan penuh sebelum deploy, lebih ketat dari gate PR.

Cache DB di CI berguna untuk kecepatan dan menghindari rate limit, tapi jangan mengunci DB terlalu lama.

### Scan ulang bukan rebuild
Scan ulang image lama hanya mendeteksi CVE baru. Rebuild yang membawa patch. Tag gcr.io/distroless/nodejs24-debian13 terus bergerak ke digest baru setiap Debian atau Node.js merilis patch, jadi image di-rebuild berkala walaupun kode tidak berubah. Kalau base image dikunci per digest, perlu bot (Dependabot atau Renovate) yang menaikkan digest secara rutin.

Pindah base image kupertimbangkan kalau ada CVE berbahaya dan terjangkau yang lama tidak di-fix, CVE tanpa fix terus menumpuk, atau distro mendekati end of life. Sebelum pindah, scan dulu kandidatnya, lalu bandingkan kecepatan vendor menambal, kompatibilitas (musl di Alpine bisa merusak modul npm native), ada shell atau tidak, dan biaya pengujian ulang.

### Blind spot Trivy
- Bug di kode sendiri (bagian Semgrep) dan perilaku runtime (bagian ZAP).
- Reachability.
- Dependency yang tidak tercatat di lock file.
- Kode vendor tanpa package.json, misalnya frontend/src/assets/private/three.js.
- Dependency frontend di image sudah di-bundle jadi JS tanpa package.json. trivy image buta terhadap CVE frontend, hanya trivy fs dengan lock file yang melihatnya. Karena itu keduanya dijalankan.

### Lock file dan --ignore-scripts
Lock file membuat versi dependency di semua mesin sama, dan di proyek nyata di-commit. Di sini tidak, karena upstream sengaja pakai package-lock=false. Saat menjalankan npm pada kode yang belum dipercaya, pakai --ignore-scripts. Script preinstall/postinstall menjalankan kode apa saja dengan hak akses user, misalnya membaca ~/.ssh atau token di env.

## Untuk fase berikutnya
- Gate: --exit-code 2 dan --severity HIGH,CRITICAL.
- Temuan Debian tanpa fix ditangani per CVE di .trivyignore dengan exp, bukan --ignore-unfixed global.
- CI butuh lock file untuk trivy fs, atau scan image sebagai sumber SCA backend.
- Perketat .dockerignore (infrastructure/, data/static/codefixes/, file spec).
- Saat menulis workflow: pin aquasecurity/trivy-action ke commit SHA, bukan tag. Cek dulu insiden kompromi tag trivy-action sekitar Maret 2026 sebelum menulisnya sebagai fakta.
