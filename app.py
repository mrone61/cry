import os
import base64
import secrets
import mimetypes
import hashlib
import time
import hmac
from collections import defaultdict
from flask import Flask, render_template, request, Response
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024

KUNCI_RAHASIA_SERVER = os.environ.get("KUNCI_RAHASIA_SERVER", "kunci-darurat-hanya-untuk-laptop")

token_sudah_dibuka = set()
percobaan_gagal = defaultdict(list)
waktu_blokir_sampai = {}

JADWAL_HUKUMAN = [60, 3600, 86400, 604800, 2592000]
CHUNK_SIZE = 64 * 1024

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

def buat_kunci_dari_password(password, salt):
    password_gabungan = password + KUNCI_RAHASIA_SERVER
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return kdf.derive(password_gabungan.encode())

def buat_kunci_file_dari_password(password, salt):
    password_gabungan = password + KUNCI_RAHASIA_SERVER
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        iterations=600000,
    )
    kunci_full = kdf.derive(password_gabungan.encode())
    return kunci_full[:32], kunci_full[32:]

def enkrip_dengan_password(data_bytes, password):
    salt = secrets.token_bytes(32)
    kunci = buat_kunci_dari_password(password, salt)
    aesgcm = AESGCM(kunci)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, data_bytes, None)
    return "PQv2." + base64.urlsafe_b64encode(salt).decode() + "." + base64.urlsafe_b64encode(nonce).decode() + "." + base64.urlsafe_b64encode(ct).decode()

def dekrip_dengan_password(token_gabungan, password):
    
    if not token_gabungan.strip().startswith("PQv2."):
        return None
    try:
        _, salt_b64, nonce_b64, ct_b64 = token_gabungan.strip().split(".", 3)
        salt = base64.urlsafe_b64decode(salt_b64)
        nonce = base64.urlsafe_b64decode(nonce_b64)
        ct = base64.urlsafe_b64decode(ct_b64)
        kunci = buat_kunci_dari_password(password, salt)
        aesgcm = AESGCM(kunci)
        return aesgcm.decrypt(nonce, ct, None)
    except Exception:
        return None

def enkrip_file_streaming(file_storage, password):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    kunci_enc, kunci_mac = buat_kunci_file_dari_password(password, salt)

    cipher = Cipher(algorithms.AES(kunci_enc), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    mac = hmac.new(kunci_mac, digestmod=hashlib.sha512)

    ciphertext_parts = []
    filename = file_storage.filename or "file"
    header = b"FILE:" + filename.encode() + b"|"
    ct_header = encryptor.update(header)
    mac.update(ct_header)
    ciphertext_parts.append(ct_header)

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
    
        mac_hitung = hmac.new(kunci_mac, ciphertext, hashlib.sha512).digest()
        if not hmac.compare_digest(mac_hitung, tag):
            return False, None, None, None
        return True, salt, nonce, ciphertext
    except Exception:
        return False, None, None, None

def generator_dekrip_file(salt, nonce, ciphertext, password, filename_info):
    kunci_enc, _ = buat_kunci_file_dari_password(password, salt)
    cipher = Cipher(algorithms.AES(kunci_enc), modes.CTR(nonce))
    decryptor = cipher.decryptor()

    for i in range(0, len(ciphertext), CHUNK_SIZE):
        potong_ct = ciphertext[i:i+CHUNK_SIZE]
        potong_plain = decryptor.update(potong_ct)
        if i == 0:
            if b"|" in potong_plain:
                _, isi = potong_plain.split(b"|", 1)
                if isi:
                    yield isi
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

                    token_sudah_dibuka.add(sidik_jari)
                    if (ip_user, sidik_jari) in percobaan_gagal:
                        del percobaan_gagal[(ip_user, sidik_jari)]

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
                    return Response(
                        generator_dekrip_file(salt, nonce, ciphertext, password, nama_file),
                        mimetype=mimetype,
                        headers={"Content-Disposition": f"attachment; filename={nama_file}"}
                    )

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
    app.run(debug=True
