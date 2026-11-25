# Fase 0: Setup

## Isi repo

| File/folder | Isi |
|---|---|
| README.md | Gambaran umum OWASP Juice Shop. |
| package.json | Metadata project, scripts, dependencies, dan versi Node yang dibutuhkan. |
| Dockerfile | Instruksi untuk membangun Docker image. |
| .gitignore | File/folder yang tidak boleh masuk ke repo git. |
| .dockerignore | File/folder yang tidak dikirim ke build context, jadi tidak ikut tersalin ke image. |
| routes/ | Logika yang menangani tiap endpoint API, bukan hanya routing. |
| frontend/ | Kode frontend. |
| data/ | Database dan seed data (user, produk, challenge). |
| .github/workflows/ | 16 workflow GitHub Actions: CI/test, release, CodeQL, dan otomasi repo. Contohnya codeql-analysis.yml jalan di setiap push ke branch mana pun dan setiap pull request. |

## Dockerfile

- Ada dua stage. Stage installer (base node:24) meng-install dependency, bersih-bersih, dan mengatur izin file. Stage akhir hanya mengambil folder /juice-shop dari installer (COPY --from=installer --chown=65532:0 /juice-shop .).
- Yang ikut ke image akhir hanya kode app dan node_modules produksi. devDependencies tidak ikut karena npm install --omit=dev, bukan karena multi-stage.
- Isi node:24 (bash, apt, curl, git, compiler), tool global (typescript, cyclonedx-npm), dan cache npm tertinggal di installer. Jadi penyerang tidak menemukan tool di image akhir, paket OS lebih sedikit, dan CVE yang perlu di-patch ikut berkurang.
- Multi-stage hanya menyaring yang ada di luar /juice-shop. File di build context seperti .env tetap tersalin ke /juice-shop lalu terbawa ke image akhir. Yang mencegahnya .dockerignore, bukan multi-stage.
- Base image akhir gcr.io/distroless/nodejs24-debian13. Attack surface kecil, tapi tanpa shell debugging jadi susah.
- Container jalan sebagai USER 65532, UID non-root.

## Yang kupelajari

### User di grup docker setara root
Daemon Docker jalan sebagai root. Siapa pun yang bisa memakai socket Docker bisa menjalankan container dengan -v /:/host dan membaca atau mengubah seluruh filesystem host. Docker hanya mengecek boleh pakai socket atau tidak, bukan boleh baca /etc/ atau tidak. USER 65532 di Dockerfile itu lapisan lain: membatasi proses di dalam container, bukan siapa yang mengendalikan daemon.

### Clone harus full history
gitleaks memindai seluruh riwayat commit, termasuk secret yang sudah dihapus. Shallow clone hanya membawa sebagian riwayat, jadi sisanya tidak terperiksa dan repo terlihat bersih padahal tidak. Di CI, actions/checkout default-nya fetch-depth 1, jadi perlu fetch-depth: 0.

### Repo baru harus kosong sebelum push
Kalau repo baru sudah berisi README atau lisensi, riwayatnya beda dengan riwayat lokal. Push ditolak (non-fast-forward), atau aku terpaksa force push.

### Workflow bawaan dimatikan
Supaya workflow yang tidak kumengerti tidak ikut jalan. Workflow itu juga butuh secret yang tidak kupunya, jadi repo penuh tanda merah dan kuota Actions terpakai. Aku akan merakit workflow sendiri dengan workflow asli sebagai referensi.

### Port diikat ke 127.0.0.1
Supaya app hanya bisa diakses dari laptop sendiri. Aku sudah membuktikannya (2026-11-25): dengan -p 3000:3000 tanpa 127.0.0.1, laptop lain di Wi-Fi yang sama bisa membuka 192.168.1.3:3000. 192.168.1.3 adalah IP laptopku di wlp0s20f3 (kolom src di ip route), bukan default gateway. Default gateway-nya router 192.168.1.1.

Bind 0.0.0.0 artinya app mendengarkan di semua interface, termasuk Wi-Fi. 0.0.0.0 bukan alamat yang dituju orang.

UFW deny 3000 tidak menahannya. Docker mengganti alamat tujuan paket ke IP container (DNAT) sebelum paket sampai ke aturan UFW. UFW hanya menjaga paket yang tujuannya laptop itu sendiri, sedangkan paket ini sudah jadi paket yang diteruskan ke container. Cara menutupnya: -p 127.0.0.1:3000:3000, aturan di chain DOCKER-USER, atau network internal tanpa -p.

Dari internet biasanya tidak bisa langsung karena router rumah (NAT) menolak koneksi masuk yang tidak diminta, kecuali ada port forwarding atau UPnP. Di server cloud yang punya IP publik, 0.0.0.0 berarti terbuka ke seluruh internet.

### node_modules lokal tidak boleh ikut build
Build context jadi besar dan lambat. node_modules lokal dikompilasi untuk OS dan versi Node di laptop, yang bisa beda dengan di container. Image juga jadi bergantung pada isi laptop, bukan package.json, jadi hasil SCA bisa tidak akurat. Ada risiko lain: node_modules lokal yang sudah diubah, misalnya lodash yang disisipi backdoor, ikut masuk ke produksi tanpa tercatat di package.json.

### Yang di-scan image buatan sendiri
Image resmi tidak mencerminkan commit-ku atau base image yang kutarik. Yang di-scan harus artifact yang benar-benar kukirim.

### Secret bocor: rotate dulu, history belakangan
Secret yang pernah bocor dianggap sudah dicuri. Menghapus history tidak menarik kembali salinan yang sudah ada di tempat lain. Urutannya:
1. Rotate: cabut secret lama di sumbernya, buat yang baru.
2. Audit: cek log pemakaian secret lama selama terekspos.
3. Baru bersihkan history, lalu pasang pencegah (gitleaks di pre-commit atau CI).

### Bare vs non-bare repo
Bare repo hanya berisi isi .git/ (riwayat dan data), tanpa working tree. Non-bare hasil git init atau git clone biasa, punya working tree. Backup dibuat bare karena:
- Tidak ada duplikasi file.
- Tidak akan teredit tanpa sengaja.
- Bare repo tujuan push yang wajar. Push ke branch yang sedang di-checkout di repo non-bare ditolak secara default (receive.denyCurrentBranch). GitHub juga menyimpan repo dalam bentuk bare.
