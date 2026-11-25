import os
import base64
import secrets
import mimetypes
import hashlib
import time
from collections import defaultdict
from flask import Flask, render_template, request
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024

# ==========================================================
# BAGIAN 1: BUKU CATATAN SERVER (MEMORY)
# ==========================================================

token_sudah_dibuka = set()
percobaan_gagal = defaultdict(list)
waktu_blokir_sampai = {}

# Jadwal hukuman: 1 menit, 1 jam, 1 hari, 7 hari, 30 hari
JADWAL_HUKUMAN = [60, 3600, 86400, 604800, 2592000]

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

# ==========================================================
# BAGIAN 2: OTAK ENKRIPSI
# ==========================================================

def buat_kunci_dari_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    kunci = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(kunci)

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

def tebak_mimetype(data_bytes, filename=""):
    if filename:
        m, _ = mimetypes.guess_type(filename)
        if m:
            return m
    if data_bytes.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg'
    if data_bytes.startswith(b'\x89PNG'):
        return 'image/png'
    if data_bytes.startswith(b'GIF8'):
        return 'image/gif'
    if data_bytes.startswith(b'RIFF') and b'WEBP' in data_bytes[:20]:
        return 'image/webp'
    if data_bytes.startswith(b'ID3') or data_bytes.startswith(b'\xff\xfb'):
        return 'audio/mpeg'
    if data_bytes.startswith(b'\x00\x00\x00') and b'ftyp' in data_bytes[:20]:
        return 'video/mp4'
    if data_bytes.startswith(b'\x1a\x45\xdf\xa3'):
        return 'video/webm'
    return 'application/octet-stream'

# ==========================================================
# BAGIAN 3: JALUR UTAMA
# ==========================================================

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
                file_bytes = file.read()
                payload = b"FILE:" + file.filename.encode() + b"|" + file_bytes
                hasil = enkrip_dengan_password(payload, password)
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
                        hasil = hasil + "\n\n[TOKEN INI SUDAH HANGUS DAN TIDAK BISA DIBUKA LAGI]"
                    elif hasil_bytes.startswith(b"FILE:"):
                        try:
                            tanpa_prefix = hasil_bytes[5:]
                            nama_file_bytes, isi_file = tanpa_prefix.split(b"|", 1)
                            hasil_filename = nama_file_bytes.decode()
                            hasil_mimetype = tebak_mimetype(isi_file, hasil_filename)
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
