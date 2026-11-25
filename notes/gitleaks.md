# gitleaks

Secret scanning di seluruh history git.

- Versi 8.30.1 dari GitHub Releases. Versi apt (8.16) kubuang karena rule-nya lama dan belum punya subcommand git/dir.
- Scan seluruh history, sekitar 24 ribu commit di semua ref, selesai dalam 5.41 detik.
- Output mentah di reports/raw/gitleaks.json. File ini tidak di-commit karena berisi secret tanpa redaksi.

## Apa yang ditemukan

Total 225 temuan.

| Rule | Jumlah |
|---|---|
| generic-api-key | 164 |
| jwt | 54 |
| private-key | 7 |

- 196 dari 225 temuan (87%) ada di file test/spec. Isinya data fixture, bukan kredensial nyata.
- 47 dari 64 file unik (73%) sudah tidak ada di working tree, tapi masih ada di history.
- 6 dari 7 private key sengaja ditanam sebagai challenge Juice Shop: lib/insecurity.js, terraform/networking.tf, infrastructure/terraform/networking.tf, test/files/passkeyVictimCredential.json. Penandanya jelas, misalnya vuln-code-snippet atau nama file insecurity.
- 1 true positive: vagrant/.vagrant/machines/default/virtualbox/private_key. Kunci SSH yang dibuat otomatis oleh Vagrant. Ter-commit 2017-03-03 ("Include latest changes"), dihapus hari yang sama ("Remove vagrant folder"), dan commit-nya hanya ada di branch gh-pages. Dampaknya rendah karena kunci ini hanya untuk VM lokal. Sekarang vagrant/.vagrant/ sudah ada di .gitignore.

## Cara menganalisa

1. Kelompokkan per rule dan per path dulu, jangan buka satu per satu dari atas.
2. Pisahkan test/fixture dari kode lain. Ini langsung menyaring 87% temuan.
3. Untuk temuan yang mencurigakan, lacak commit-nya: kapan masuk, kapan dihapus, di branch mana.
4. Tentukan kategorinya: TP, accepted, atau FP.
5. Nilai validitas dan severity secara terpisah.

## Insight

### Tiga kategori temuan
- TP: secret asli yang ter-commit tanpa sengaja. Harus di-rotate.
- Accepted (by design): secret asli, tapi memang sengaja ditaruh, misalnya kunci challenge. 6 private key Juice Shop masuk sini, bukan FP, karena detektornya benar menemukan kunci asli. Di-ignore per temuan dan alasannya dicatat.
- FP: bukan secret sama sekali, misalnya string fixture yang kebetulan cocok dengan regex. Artinya detektornya yang salah.

### Validitas dan severity itu terpisah
TP atau FP menjawab "apakah ini secret asli yang ter-commit tanpa sengaja". Severity menjawab "seberapa parah kalau dipakai orang". Kunci Vagrant itu TP dengan severity rendah. Fakta bahwa kunci itu dihapus di hari yang sama malah memperkuat TP, karena itu tanda commit-nya tidak sengaja.

### File yang sudah dihapus tetap masalah
Menghapus file hanya membuat commit baru yang bilang "file ini sudah tidak ada". Commit lamanya tetap utuh dan bisa dibaca siapa pun yang punya clone, fork, atau mirror. Kalau hanya memindai file saat ini (gitleaks dir), kunci Vagrant tidak akan ketemu. Kunci itu muncul lewat gitleaks git, yang menelusuri semua commit di semua ref.

Salinannya juga tidak cuma di clone orang lain. Fork di GitHub berbagi object dengan repo asalnya, GitHub masih bisa menyajikan commit lama lewat SHA atau ref PR, log dan artefak CI bisa ikut memuatnya, dan bot memindai push publik dalam hitungan detik. Jadi git filter-repo plus force push itu kebersihan, bukan remediasi. Urutannya rotate, audit log akses, baru bersihkan history. Kalau dibalik, kuncinya masih valid selama aku sibuk membersihkan history.

### Kenapa kunci Vagrant ketemu tanpa --mirror
Clone biasa (bukan shallow, bukan --single-branch) sudah membawa gh-pages sebagai refs/remotes/origin/gh-pages, dan gitleaks git secara default menelusuri semua ref. Yang akan melewatkannya: shallow clone (default actions/checkout, fetch-depth 1) atau --single-branch. --mirror baru berbeda kalau ada ref non-branch seperti refs/pull/* dari PR yang belum di-merge.

### Cara gitleaks memutuskan sesuatu itu secret
- Keywords: prefilter untuk performa. Regex sebuah rule baru dijalankan kalau teksnya mengandung keyword rule itu, misalnya akia untuk AWS.
- Regex: tiap rule punya pola untuk satu jenis secret.
- Entropy: nilai yang tidak cukup acak (password123, changeme) dibuang.
- Allowlist dan stopwords membuang match yang sudah dikenal aman.

generic-api-key paling banyak FP karena cuma mengandalkan konteks: nama variabel mengandung key, token, secret, atau password, lalu ada = atau :, lalu nilai acak. Hash, UUID, dan token fixture ikut kena. Recall tinggi, precision rendah. Sebaliknya AWS access key punya format ketat (prefix AKIA atau ASIA, lalu tepat 16 karakter huruf besar dan angka), jadi jarang FP. Prefix seperti AKIA, ghp_, atau sk_live_ memang sengaja dibuat vendor supaya mudah dideteksi.

### Ignore yang aman, dari yang paling sempit
- .gitleaksignore: abaikan satu temuan lewat fingerprint (commit:file:rule:line). Secret baru di file yang sama tetap ketemu.
- Allowlist sempit di config: satu path, dibatasi ke rule tertentu (targetRules), atau regex untuk nilai fake yang sudah dikenal.
- Baseline (--baseline-path): report lama jadi baseline, gate hanya gagal kalau ada temuan baru. Cocok untuk repo dengan history kotor seperti Juice Shop.

Allowlist seluruh test/ berbahaya. Secret asli yang masuk ke test/ tidak akan kelihatan, regex path-nya bisa ikut mencocokkan folder lain, dan allowlist itu permanen dan diam. Prinsipnya: ignore apa yang sudah diperiksa, bukan tempat yang belum diperiksa.

### Exit code dan fail-closed
gitleaks keluar 1 untuk leak dan juga untuk error. Kalau gate masih mode report-only dan kode 1 dianggap "ada leak, biarkan", config typo atau scanner crash ikut dibiarkan. Pipeline tetap hijau padahal scan tidak pernah jalan. Itu fail-open. Solusinya --exit-code 2: leak keluar 2, error tetap 1. Di bash tinggal case $? (0 lolos, 2 gagal karena leak, selain itu gagal karena scanner error). Error scanner harus selalu gagal (fail-closed), walaupun leak sedang mode report-only.

### Posisi secret scanning
Dipasang berlapis karena tiap posisi punya celah:
- Pre-commit hook (gitleaks git --staged): paling awal, tapi sukarela. Hook tidak ikut ter-clone, bisa dilewati dengan --no-verify, dan tidak semua perubahan lewat laptop.
- Push protection di server: menolak push sebelum secret masuk remote, tapi hanya untuk pola yang presisi tinggi dan bisa di-bypass dengan alasan.
- CI: jalan setelah push, jadi secret sudah ada di remote. CI hanya mendeteksi, tapi config-nya seragam dan tidak bisa dilewati developer.
- Scan terjadwal seluruh history: rule baru bisa menemukan secret lama yang dulu lolos.

## Untuk fase berikutnya
- Gate: --exit-code 2, error scanner fail-closed.
- Baseline untuk history lama, supaya hanya leak baru yang memblokir.
- CI checkout dengan fetch-depth: 0.
- Commit hanya report yang sudah di-redact (--redact) plus ringkasan.
