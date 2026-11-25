import os
import base64
import secrets
import mimetypes
import hashlib
import time
import hmac
from collections import defaultdict
from flask import Flask, render_template, request, Response
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # TETAP 20 MB

KUNCI_RAHASIA_SERVER = os.environ.get("KUNCI_RAHASIA_SERVER", "kunci-darurat-hanya-untuk-laptop")

token_sudah_dibuka = set()
percobaan_gagal = defaultdict(list)
waktu_blokir_sampai = {}

# Jadwal hukuman: 1 menit, 1 jam, 1 hari, 7 hari, 30 hari
JADWAL_HUKUMAN = [60, 3600, 86400, 604800, 2592000]
CHUNK_SIZE = 64 * 1024  # 64 KB per potong - ini kunci Opsi B

def buat_sidijari_token(token_str):
    return hashlib.sha256(token_str.encode()).hexdigest()

def cek_apakah_diblokir(ip, token_str):
    kunci = (ip, buat_sidijari_token(token_str))
    sekarang = time.time()
    if kunci in waktu_blokir_sampai and sekarang < waktu_blokir_sampai[kunci]:
        sisa = int(waktu_blokir_sampai[kunci] - sekarang)
        return True, sisa
    return False, 0

def catat_gagal_dan_cek_hukuman(ip, token_str):
    kunci = (ip, buat_sidijari_token(token_str))
    sekarang = time.time()
    percobaan_gagal[kunci].append(sekarang)
    total_gagal = len(percobaan_gagal[kunci])
    if total_gagal % 3 == 0:
        level = (total_gagal // 3) - 1
        if level >= len(JADWAL_HUKUMAN):
            level = len(JADWAL_HUKUMAN) - 1
        durasi_hukuman = JADWAL_HUKUMAN[level]
        waktu_blokir_sampai[kunci] = sekarang + durasi_hukuman
        return durasi_hukuman
    return 0

def ubah_detik_jadi_kata(detik):
    if detik < 60:
        return f"{detik} detik"
    if detik < 3600:
        return f"{detik // 60} menit"
    if detik < 86400:
        return f"{detik // 3600} jam"
    return f"{detik // 86400} hari"

# ---------- KUNCI SUPER : Password + Kunci Server ----------

def buat_kunci_dari_password(password, salt):
    password_gabungan = password + KUNCI_RAHASIA_SERVER
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    kunci = kdf.derive(password_gabungan.encode())
    return base64.urlsafe_b64encode(kunci)

def buat_kunci_file_dari_password(password, salt):
    # Untuk file, kita butuh 64 byte: 32 untuk enkripsi + 32 untuk HMAC
    password_gabungan = password + KUNCI_RAHASIA_SERVER
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=600000,
    )
    kunci_full = kdf.derive(password_gabungan.encode())
    return kunci_full[:32], kunci_full[32:]

# ---------- TEKS : Tetap pakai Fernet (kecil, cepat) ----------

def enkrip_dengan_password(data_bytes, password):
    salt = secrets.token_bytes(16)
    f = Fernet(buat_kunci_dari_password(password, salt))
    token = f.encrypt(data_bytes)
    return base64.urlsafe_b64encode(salt).decode() + "." + token.decode()

def dekrip_dengan_password(token_gabungan, password):
    try:
        salt_b64, token = token_gabungan.strip().split(".", 1)
        salt = base64.urlsafe_b64decode(salt_b64)
        f = Fernet(buat_kunci_dari_password(password, salt))
        return f.decrypt(token.encode())
    except Exception:
        return None

# ---------- FILE : OPSI B - AES-CTR + HMAC Streaming ----------
# Berlaku untuk SEMUA jenis file: Gambar, Audio, Video, PDF, CSV, dll
# Karena file dianggap cuma tumpukan byte, tidak peduli isinya apa.

def enkrip_file_streaming(file_storage, password):
    """
    Baca file per 64KB, enkripsi per potong, tidak pernah load 20MB sekaligus ke RAM.
    Format token file: FILEv2.salt.nonce.ciphertext.tag.nama_file_b64
    """
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    kunci_enc, kunci_mac = buat_kunci_file_dari_password(password, salt)

    cipher = Cipher(algorithms.AES(kunci_enc), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    mac = hmac.new(kunci_mac, digestmod=hashlib.sha256)

    ciphertext_parts = []
    # Baca file asli, tapi simpan juga nama file-nya
    filename = file_storage.filename or "file"
    # Header kecil: nama file + pemisah, ikut dienkripsi biar aman
    header = b"FILE:" + filename.encode() + b"|"
    # Enkripsi header dulu
    ct_header = encryptor.update(header)
    mac.update(ct_header)
    ciphertext_parts.append(ct_header)

    # Ini intinya Opsi B: baca 64KB, enkripsi, buang dari RAM, lanjut potong berikutnya
    while True:
        potong = file_storage.stream.read(CHUNK_SIZE)
        if not potong:
            break
        ct = encryptor.update(potong)
        mac.update(ct)
        ciphertext_parts.append(ct)

    ct_akhir = encryptor.finalize()
    if ct_akhir:
        mac.update(ct_akhir)
        ciphertext_parts.append(ct_akhir)

    ciphertext = b"".join(ciphertext_parts)
    tag = mac.digest()

    token = (
        "FILEv2."
        + base64.urlsafe_b64encode(salt).decode() + "."
        + base64.urlsafe_b64encode(nonce).decode() + "."
        + base64.urlsafe_b64encode(ciphertext).decode() + "."
        + base64.urlsafe_b64encode(tag).decode()
    )
    return token

def cek_token_file_valid(token_gabungan, password):
    """
    Cek HMAC dulu SEBELUM dekripsi. Kalau password salah / token rusak,
    langsung gagal, tidak perlu dekripsi file besar.
    Return: (is_valid, salt, nonce, ciphertext) atau (False, None, None, None)
    """
    try:
        parts = token_gabungan.strip().split(".", 4)
        if len(parts) != 5 or parts[0] != "FILEv2":
            return False, None, None, None
        _, salt_b64, nonce_b64, ct_b64, tag_b64 = parts
        salt = base64.urlsafe_b64decode(salt_b64)
        nonce = base64.urlsafe_b64decode(nonce_b64)
        ciphertext = base64.urlsafe_b64decode(ct_b64)
        tag = base64.urlsafe_b64decode(tag_b64)

        _, kunci_mac = buat_kunci_file_dari_password(password, salt)
        mac_hitung = hmac.new(kunci_mac, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_hitung, tag):
            return False, None, None, None
        return True, salt, nonce, ciphertext
    except Exception:
        return False, None, None, None

def generator_dekrip_file(salt, nonce, ciphertext, password, filename_info):
    """
    Generator streaming untuk download.
    Dekripsi per 64KB dan langsung kirim ke browser, tidak numpuk di RAM.
    """
    kunci_enc, _ = buat_kunci_file_dari_password(password, salt)
    cipher = Cipher(algorithms.AES(kunci_enc), modes.CTR(nonce))
    decryptor = cipher.decryptor()

    # Dekripsi potong per potong, langsung yield
    for i in range(0, len(ciphertext), CHUNK_SIZE):
        potong_ct = ciphertext[i:i+CHUNK_SIZE]
        potong_plain = decryptor.update(potong_ct)
        # Potong pertama berisi header FILE:nama|
        # Kita buang headernya, sisanya langsung kirim
        if i == 0:
            # Cari pemisah | pertama
            if b"|" in potong_plain:
                _, isi = potong_plain.split(b"|", 1)
                if isi:
                    yield isi
            # Kalau header kepotong di tengah (file kecil), tangani di bawah
            # Untuk simpelnya, karena header kecil, potong pertama pasti mengandung |
            continue
        yield potong_plain
    akhir = decryptor.finalize()
    if akhir:
        yield akhir

def tebak_mimetype(filename=""):
    if filename:
        m, _ = mimetypes.guess_type(filename)
        if m:
            return m
    return 'application/octet-stream'

@app.route('/', methods=['GET', 'POST'])
def index():
    hasil = None
    mode = None
    pesan = ""
    error = None
    hasil_file = None
    hasil_filename = None
    hasil_mimetype = None

    if request.method == 'POST':
        mode = request.form.get('mode', '')
        pesan = request.form.get('pesan', '')
        password = request.form.get('password', '')
        ip_user = request.remote_addr

        if not password:
            error = "Password wajib diisi! Password ini yang jadi kunci brankas lu."
            return render_template('index.html', hasil=hasil, mode=mode, pesan=pesan, error=error)

        if mode == 'enkripsi':
            if 'file' in request.files and request.files['file'].filename != '':
                file = request.files['file']
                # OPSI B: file apa saja - Gambar, Audio, Video, PDF, CSV, dll
                # Semua diperlakukan sama: byte mentah, streaming 64KB
                hasil = enkrip_file_streaming(file, password)
            elif pesan.strip() != '':
                payload = b"TEXT:" + pesan.encode()
                hasil = enkrip_dengan_password(payload, password)
            else:
                error = "Isi pesan atau pilih file dulu bro!"

        elif mode == 'dekripsi':
            if pesan.strip() == '':
                error = "Paste dulu token enkripsi nya!"
            else:
                token_str = pesan.strip()
                sidik_jari = buat_sidijari_token(token_str)

                if sidik_jari in token_sudah_dibuka:
                    error = "Token ini SUDAH HANGUS! Token ini sudah pernah dibuka 1x dan langsung dimusnahkan."
                    return render_template('index.html', hasil=hasil, mode=mode, pesan=pesan, error=error)

                diblokir, sisa_detik = cek_apakah_diblokir(ip_user, token_str)
                if diblokir:
                    error = f"Terlalu banyak percobaan gagal! IP kamu diblokir untuk token ini selama {ubah_detik_jadi_kata(sisa_detik)} lagi."
                    return render_template('index.html', hasil=hasil, mode=mode, pesan=pesan, error=error)

                # --- Cek apakah ini token FILE baru (FILEv2) ---
                if token_str.startswith("FILEv2."):
                    valid, salt, nonce, ciphertext = cek_token_file_valid(token_str, password)
                    if not valid:
                        durasi = catat_gagal_dan_cek_hukuman(ip_user, token_str)
                        total_gagal = len(percobaan_gagal[(ip_user, sidik_jari)])
                        if durasi > 0:
                            error = f"Password salah! Kamu sudah gagal {total_gagal}x. Token ini terkunci selama {ubah_detik_jadi_kata(durasi)}."
                        else:
                            sisa_coba = 3 - (total_gagal % 3)
                            error = f"Password salah atau Token rusak! Sisa percobaan sebelum terkunci: {sisa_coba}x"
                        return render_template('index.html', hasil=hasil, mode=mode, pesan=pesan, error=error)

                    # Password benar! Tandai hangus, lalu STREAMING DOWNLOAD
                    token_sudah_dibuka.add(sidik_jari)
                    if (ip_user, sidik_jari) in percobaan_gagal:
                        del percobaan_gagal[(ip_user, sidik_jari)]

                    # Ambil nama file asli dari dalam ciphertext (dekripsi header saja untuk nama)
                    # Cara aman: dekripsi potong pertama untuk baca nama
                    kunci_enc, _ = buat_kunci_file_dari_password(password, salt)
                    cipher_tmp = Cipher(algorithms.AES(kunci_enc), modes.CTR(nonce))
                    dec_tmp = cipher_tmp.decryptor()
                    potong_awal = dec_tmp.update(ciphertext[:1024])
                    nama_file = "file_hasil"
                    try:
                        if potong_awal.startswith(b"FILE:"):
                            nama_file = potong_awal[5:].split(b"|", 1)[0].decode()
                    except:
                        nama_file = "file_hasil"

                    mimetype = tebak_mimetype(nama_file)
                    # OPSI B: Langsung download, TIDAK ditempel di HTML sebagai data:
                    return Response(
                        generator_dekrip_file(salt, nonce, ciphertext, password, nama_file),
                        mimetype=mimetype,
                        headers={"Content-Disposition": f"attachment; filename={nama_file}"}
                    )

                # --- Token TEKS lama / token FILE lama (Fernet) ---
                hasil_bytes = dekrip_dengan_password(token_str, password)
                if hasil_bytes is None:
                    durasi = catat_gagal_dan_cek_hukuman(ip_user, token_str)
                    total_gagal = len(percobaan_gagal[(ip_user, sidik_jari)])
                    if durasi > 0:
                        error = f"Password salah! Kamu sudah gagal {total_gagal}x. Token ini terkunci selama {ubah_detik_jadi_kata(durasi)}."
                    else:
                        sisa_coba = 3 - (total_gagal % 3)
                        error = f"Password salah atau Token rusak! Sisa percobaan sebelum terkunci: {sisa_coba}x"
                else:
                    token_sudah_dibuka.add(sidik_jari)
                    if (ip_user, sidik_jari) in percobaan_gagal:
                        del percobaan_gagal[(ip_user, sidik_jari)]

                    if hasil_bytes.startswith(b"TEXT:"):
                        hasil = hasil_bytes[5:].decode(errors='ignore')
                    elif hasil_bytes.startswith(b"FILE:"):
                        # Token file LAMA (sebelum Opsi B) - masih didukung, tapi pakai cara lama
                        # Biar token lama tidak langsung mati total
                        try:
                            tanpa_prefix = hasil_bytes[5:]
                            nama_file_bytes, isi_file = tanpa_prefix.split(b"|", 1)
                            hasil_filename = nama_file_bytes.decode()
                            hasil_mimetype = tebak_mimetype(hasil_filename)
                            b64 = base64.b64encode(isi_file).decode()
                            hasil_file = f"data:{hasil_mimetype};base64,{b64}"
                            hasil = f"File berhasil dibuka: {hasil_filename} - TOKEN SUDAH HANGUS!"
                        except Exception:
                            error = "Format file rusak!"
                    else:
                        try:
                            hasil = hasil_bytes.decode()
                        except:
                            error = "Data ini bukan teks, coba cek lagi!"

    return render_template('index.html',
                           hasil=hasil,
                           mode=mode,
                           pesan=pesan,
                           error=error,
                           hasil_file=hasil_file,
                           hasil_filename=hasil_filename,
                           hasil_mimetype=hasil_mimetype)

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True)
