# NOTES

Catatan belajarku selama membangun pipeline DevSecOps di atas OWASP Juice Shop. Ini bukan dokumentasi lengkap, isinya hal-hal yang benar-benar kupahami setelah menjalankan tiap tool sendiri. Temuan, cara analisa, dan detailnya ada di folder notes/.

| Bagian | Detail |
|---|---|
| Fase 0: setup | [notes/setup.md](notes/setup.md) |
| gitleaks (secret scanning) | [notes/gitleaks.md](notes/gitleaks.md) |
| Semgrep (SAST) | [notes/semgrep.md](notes/semgrep.md) |
| Trivy (SCA) | [notes/trivy.md](notes/trivy.md) |
| ZAP (DAST) | [notes/zap.md](notes/zap.md) |

## Setup

- Repo ini snapshot beku dari Juice Shop di commit 717f5efa8 (v20.3.0+7). Semua temuan terikat ke versi kode itu.
- Akses ke socket Docker sama dengan akses root. Daemon jalan sebagai root, jadi siapa pun yang bisa pakai socket bisa mount / ke container.
- Multi-stage build cuma membuang yang ada di luar folder app. File seperti .env tetap ikut ke image kalau tidak masuk .dockerignore.
- Port harus diikat ke 127.0.0.1. Aku sudah coba sendiri: dengan -p 3000:3000, laptop lain di Wi-Fi yang sama bisa membuka app-ku, dan UFW tidak menahannya karena Docker membelokkan paket sebelum sampai ke UFW.
- Secret yang bocor anggap sudah dicuri. Rotate dulu, audit, baru bersihkan history.

## Yang berlaku di semua tool

- Exit 0 tidak berarti aman. Tiap tool punya aturan exit code sendiri: gitleaks pakai 1 untuk leak dan error, Semgrep dan Trivy default 0 walaupun ada temuan, ZAP pakai 1 untuk FAIL, 2 untuk WARN, 3 untuk error. Gate harus bisa membedakan "ada temuan" dan "scanner rusak", dan scanner rusak harus selalu gagal.
- Scan bersih bisa berarti tool-nya buta. trivy fs pertama 0 CVE karena tidak ada lock file. ZAP kehilangan 4 rule tanpa error. Semgrep gagal parse 54 file dan tetap exit 0. Selain hasil, cek juga apakah tool benar-benar melihat semuanya.
- Temuan ada tiga kategori: benar dan harus diperbaiki, benar tapi diterima (sengaja ditanam atau risikonya kecil), dan FP (tool-nya salah). Temuan benar jangan dicap FP, karena FP diabaikan selamanya.
- Severity bukan prioritas. Severity dari tool atau CVSS itu tanpa konteks. Prioritas ditentukan konteks: terjangkau atau tidak, sudah ada exploit nyata atau tidak, sudah ada fix atau tidak, siapa yang bisa menjangkau app.
- Ignore yang aman itu sempit, ada alasannya, dan bisa ditinjau lagi. Ignore per temuan, bukan per folder. Ignore apa yang sudah diperiksa, bukan tempat yang belum diperiksa.
- Baseline: utang lama diterima, temuan baru diblokir. gitleaks punya --baseline-path, Semgrep punya --baseline-commit. Trivy tidak punya, jadi dibandingkan dengan hasil scan main.
- Hasil bisa berubah tanpa kode berubah, karena registry rule Semgrep, DB Trivy, dan add-on ZAP terus diperbarui. Catat versi dan tanggal scan.
- Triage mulai dari mengelompokkan per rule, folder, dan severity, bukan membaca satu per satu dari atas.

## gitleaks

gitleaks mencari secret pakai keyword, regex, dan entropy di seluruh history git. Pelajaran terbesarku: menghapus file tidak menghapus secret. Kunci SSH Vagrant yang ter-commit tahun 2017 dan dihapus di hari yang sama tetap ketemu, karena commit lamanya masih ada. Salinannya juga sudah tersebar ke clone, fork, dan cache, jadi yang benar adalah rotate, bukan sekadar membersihkan history.

generic-api-key paling berisik karena polanya longgar. Secret scanning juga perlu dipasang berlapis (pre-commit, push protection, CI, scan terjadwal), karena tiap posisi punya celah.

## Semgrep

Semgrep membaca kode dan melacak data dari source ke sink. SQLi di routes/search.ts membuatku paham bahwa memotong panjang input bukan sanitizer, dan parameterized query berhasil karena memisahkan struktur query dari data.

Tapi Semgrep hanya menemukan apa yang dimodelkan rule-nya. NoSQL injection di MarsDB lolos karena tidak ada rule untuk sink itu. IDOR dan obfuscation juga lolos, karena bug-nya berupa pengecekan yang tidak ada atau cacat desain, bukan pola kode. Di Mongo, penyerang mengirim struktur lewat object JSON, bukan sintaks lewat tanda kutip, jadi validasi tipe yang menutupnya.

## Trivy

Trivy membuat daftar paket lalu mencocokkannya ke database CVE. Trivy tidak membaca kode, jadi tidak tahu apakah fungsi yang rentan dipakai. crypto-js bernilai CRITICAL, tapi PBKDF2-nya tidak pernah dipanggil, jadi prioritasnya rendah. Gate yang cuma melihat severity bisa terbalik: CRITICAL yang tidak terjangkau diblokir, sedangkan HIGH yang sudah dieksploitasi lolos.

Yang juga baru kupahami: dependency transitive diperbaiki lewat induknya atau overrides, bukan install langsung di root. Scan ulang hanya mendeteksi, rebuild yang membawa patch. trivy fs dan trivy image melihat benda yang berbeda, jadi keduanya dijalankan.

## ZAP

ZAP menguji app yang sedang jalan dari luar. Baseline disebut pasif, tapi spider tetap mengirim request nyata. Aku menjalankannya di network Docker internal supaya Juice Shop tidak bisa keluar, dan ternyata isolasi itu diam-diam mematikan 4 rule beta yang butuh internet. Exit code tidak berubah, jadi jumlah rule yang di-load juga harus dicek.

ACAO * terlihat berbahaya, tapi tidak cukup untuk mencuri sesi, karena aturan CORS melarang wildcard dipakai bersama kredensial. Spider klasik buta terhadap route SPA, dan itu masalah penemuan URL yang ditutup dengan AJAX spider, bukan dengan active scan. Rule berbasis signature juga tidak mengenal stack trace Express.

## SAST vs DAST

- SAST jalan lebih awal, memberi lokasi bug yang pasti, dan melihat kode yang tidak terjangkau lewat UI. FP-nya lebih banyak.
- DAST melihat hal yang baru ada saat runtime (header, cookie, pesan error) dan bisa membuktikan bug benar-benar bisa dieksploitasi. Tapi DAST hanya melihat apa yang ditemukan spider.
- Ada yang tidak ditemukan tool mana pun: logika bisnis, IDOR, dan race condition. Untuk itu butuh review manual dan pentest.

## Berikutnya

Fase 2: workflow GitHub Actions sendiri, satu job per tool, mulai dari gitleaks dan Semgrep. Daftar keputusan untuk gate dan CI ada di bagian "Untuk fase berikutnya" di tiap file notes/.
