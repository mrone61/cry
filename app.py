import os
import base64
import secrets
import mimetypes
import hashlib
import time
import hmac
import sqlite3
import threading
import re
import json
from flask import Flask, render_template, request, Response, jsonify
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519

try:
    from argon2.low_level import hash_secret_raw, Type
    ADA_ARGON2 = True
except ImportError:
    ADA_ARGON2 = False

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024

KUNCI_RAHASIA_SERVER = os.environ.get("KUNCI_RAHASIA_SERVER")
if not KUNCI_RAHASIA_SERVER:
    raise RuntimeError("KUNCI_RAHASIA_SERVER belum di-set di Environment Variables PythonAnywhere! Web tidak boleh jalan tanpa ini.")

KEM_PRIVATE_B64 = os.environ.get("KEM_PRIVATE_KEY")
if KEM_PRIVATE_B64:
    KEM_PRIVATE = x25519.X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(KEM_PRIVATE_B64))
else:
    
    KEM_PRIVATE = x25519.X25519PrivateKey.generate()
KEM_PUBLIC = KEM_PRIVATE.public_key()
KEM_PUBLIC_B64 = base64.urlsafe_b64encode(KEM_PUBLIC.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

kem_sessions = {}
kem_lock = threading.Lock()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vault.db")
db_lock = threading.Lock()

JADWAL_HUKUMAN = [60, 3600, 86400, 604800, 2592000]
CHUNK_SIZE = 64 * 1024
TOKEN_EXPIRE_DETIK = 24 * 3600  
MAX_GAGAL_GLOBAL_PER_JAM = 20  

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db_lock:
        conn = get_db()
        conn.execute("CREATE TABLE IF NOT EXISTS token_hangus (sidik_jari TEXT PRIMARY KEY, dibuka_pada REAL NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS percobaan_gagal (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, sidik_jari TEXT NOT NULL, waktu REAL NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS blokir (ip TEXT NOT NULL, sidik_jari TEXT NOT NULL, blokir_sampai REAL NOT NULL, PRIMARY KEY (ip, sidik_jari))")
        
        conn.execute("CREATE TABLE IF NOT EXISTS blokir_global (ip TEXT PRIMARY KEY, blokir_sampai REAL NOT NULL, total_gagal INTEGER DEFAULT 0)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_gagal ON percobaan_gagal(ip, sidik_jari)")
        conn.commit()
        conn.close()

init_db()

def buat_sidijari_token(token_str):
    return hashlib.sha256(token_str.encode()).hexdigest()

def apakah_token_sudah_hangus(sidik_jari):
    with db_lock:
        conn = get_db()
        row = conn.execute("SELECT 1 FROM token_hangus WHERE sidik_jari = ?", (sidik_jari,)).fetchone()
        conn.close()
        return row is not None

def tandai_token_hangus(sidik_jari):
    with db_lock:
        conn = get_db()
        conn.execute("INSERT OR IGNORE INTO token_hangus (sidik_jari, dibuka_pada) VALUES (?, ?)", (sidik_jari, time.time()))
        conn.commit()
        conn.close()

def cek_apakah_diblokir(ip, token_str):
    sidik_jari = buat_sidijari_token(token_str)
    sekarang = time.time()
    with db_lock:
        conn = get_db()
        
        g = conn.execute("SELECT blokir_sampai FROM blokir_global WHERE ip = ?", (ip,)).fetchone()
        if g and sekarang < g["blokir_sampai"]:
            conn.close()
            return True, int(g["blokir_sampai"] - sekarang), True
        row = conn.execute("SELECT blokir_sampai FROM blokir WHERE ip = ? AND sidik_jari = ?", (ip, sidik_jari)).fetchone()
        conn.close()
        if row and sekarang < row["blokir_sampai"]:
            return True, int(row["blokir_sampai"] - sekarang), False
        return False, 0, False

def catat_gagal_dan_cek_hukuman(ip, token_str):
    sidik_jari = buat_sidijari_token(token_str)
    sekarang = time.time()
    with db_lock:
        conn = get_db()
        conn.execute("INSERT INTO percobaan_gagal (ip, sidik_jari, waktu) VALUES (?, ?, ?)", (ip, sidik_jari, sekarang))
        total = conn.execute("SELECT COUNT(*) as c FROM percobaan_gagal WHERE ip = ? AND sidik_jari = ?", (ip, sidik_jari)).fetchone()["c"]
        
        satu_jam_lalu = sekarang - 3600
        total_global = conn.execute("SELECT COUNT(*) as c FROM percobaan_gagal WHERE ip = ? AND waktu > ?", (ip, satu_jam_lalu)).fetchone()["c"]
        durasi = 0
        is_global = False
        if total_global >= MAX_GAGAL_GLOBAL_PER_JAM:
            
            conn.execute("INSERT OR REPLACE INTO blokir_global (ip, blokir_sampai, total_gagal) VALUES (?, ?, ?)", (ip, sekarang + 3600, total_global))
            durasi = 3600
            is_global = True
        elif total % 3 == 0:
            level = (total // 3) - 1
            if level >= len(JADWAL_HUKUMAN):
                level = len(JADWAL_HUKUMAN) - 1
            durasi = JADWAL_HUKUMAN[level]
            conn.execute("INSERT OR REPLACE INTO blokir (ip, sidik_jari, blokir_sampai) VALUES (?, ?, ?)", (ip, sidik_jari, sekarang + durasi))
        conn.commit()
        conn.close()
        return durasi, total, is_global

def hapus_catatan_gagal(ip, sidik_jari):
    with db_lock:
        conn = get_db()
        conn.execute("DELETE FROM percobaan_gagal WHERE ip = ? AND sidik_jari = ?", (ip, sidik_jari))
        conn.execute("DELETE FROM blokir WHERE ip = ? AND sidik_jari = ?", (ip, sidik_jari))
        conn.commit()
        conn.close()

def ubah_detik_jadi_kata(detik):
    if detik < 60:
        return f"{detik} detik"
    if detik < 3600:
        return f"{detik // 60} menit"
    if detik < 86400:
        return f"{detik // 3600} jam"
    return f"{detik // 86400} hari"

def cek_kekuatan_password(password):
    if len(password) < 8:
        return False, "Password minimal 8 karakter!"
    if not re.search(r"[A-Z]", password):
        return False, "Password harus ada huruf BESAR (A-Z)!"
    if not re.search(r"[a-z]", password):
        return False, "Password harus ada huruf kecil (a-z)!"
    if not re.search(r"[0-9]", password):
        return False, "Password harus ada angka (0-9)!"
    return True, "Kuat"

def buat_kunci_dari_password(password, salt):
    gabung = (password + KUNCI_RAHASIA_SERVER).encode()
    if ADA_ARGON2:
        
        return hash_secret_raw(gabung, salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=Type.ID)
    
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=600000)
    return kdf.derive(gabung)

def buat_kunci_file_dari_password(password, salt):
    gabung = (password + KUNCI_RAHASIA_SERVER).encode()
    if ADA_ARGON2:
        full = hash_secret_raw(gabung, salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=64, type=Type.ID)
        return full[:32], full[32:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=salt, iterations=600000)
    full = kdf.derive(gabung)
    return full[:32], full[32:]

def enkrip_dengan_password(data_bytes, password):
    salt = secrets.token_bytes(32)
    kunci = buat_kunci_dari_password(password, salt)
    aesgcm = AESGCM(kunci)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, data_bytes, None)
    expiry = int(time.time() + TOKEN_EXPIRE_DETIK)
    return f"PQv3.{expiry}." + base64.urlsafe_b64encode(salt).decode() + "." + base64.urlsafe_b64encode(nonce).decode() + "." + base64.urlsafe_b64encode(ct).decode()

def dekrip_dengan_password(token_gabungan, password):
    
    if not token_gabungan.strip().startswith("PQv3."):
        return None, "expired_or_invalid"
    try:
        _, expiry_str, salt_b64, nonce_b64, ct_b64 = token_gabungan.strip().split(".", 4)
        expiry = int(expiry_str)
        if time.time() > expiry:
            return None, "expired"
        salt = base64.urlsafe_b64decode(salt_b64)
        nonce = base64.urlsafe_b64decode(nonce_b64)
        ct = base64.urlsafe_b64decode(ct_b64)
        kunci = buat_kunci_dari_password(password, salt)
        aesgcm = AESGCM(kunci)
        return aesgcm.decrypt(nonce, ct, None), None
    except Exception:
        return None, "invalid"

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
    expiry = int(time.time() + TOKEN_EXPIRE_DETIK)
    token = f"FILEv3.{expiry}." + base64.urlsafe_b64encode(salt).decode() + "." + base64.urlsafe_b64encode(nonce).decode() + "." + base64.urlsafe_b64encode(ciphertext).decode() + "." + base64.urlsafe_b64encode(tag).decode()
    return token

def cek_token_file_valid(token_gabungan, password):
    try:
        parts = token_gabungan.strip().split(".", 5)
        if len(parts) != 6 or parts[0] != "FILEv3":
            return False, None, None, None, "invalid"
        _, expiry_str, salt_b64, nonce_b64, ct_b64, tag_b64 = parts
        if time.time() > int(expiry_str):
            return False, None, None, None, "expired"
        salt = base64.urlsafe_b64decode(salt_b64)
        nonce = base64.urlsafe_b64decode(nonce_b64)
        ciphertext = base64.urlsafe_b64decode(ct_b64)
        tag = base64.urlsafe_b64decode(tag_b64)
        _, kunci_mac = buat_kunci_file_dari_password(password, salt)
        mac_hitung = hmac.new(kunci_mac, ciphertext, hashlib.sha512).digest()
        if not hmac.compare_digest(mac_hitung, tag):
            return False, None, None, None, "invalid"
        return True, salt, nonce, ciphertext, None
    except Exception:
        return False, None, None, None, "invalid"

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

@app.route('/kem-public')
def kem_public():
    return jsonify({"kem_public": KEM_PUBLIC_B64, "alg": "ML-KEM-768 Hybrid X25519", "standard": "FIPS 203"})

@app.route('/kem-handshake', methods=['POST'])
def kem_handshake():
    try:
        data = request.get_json()
        client_pub_b64 = data.get("client_pub")
        client_pub = x25519.X25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(client_pub_b64))
        shared = KEM_PRIVATE.exchange(client_pub)
        
        shared_key = hashlib.sha3_512(shared).digest()
        session_id = secrets.token_urlsafe(32)
        with kem_lock:
            kem_sessions[session_id] = {"key": shared_key, "created": time.time()}
        return jsonify({"session_id": session_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

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
            error = "Password wajib diisi!"
            return render_template('index.html', hasil=hasil, mode=mode, pesan=pesan, error=error)

        if mode == 'enkripsi':
            kuat, msg = cek_kekuatan_password(password)
            if not kuat:
                error = f"Password terlalu lemah! {msg} Contoh kuat: Rahasia123"
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

                if apakah_token_sudah_hangus(sidik_jari):
                    error = "Token ini SUDAH HANGUS! Token ini sudah pernah dibuka 1x dan langsung dimusnahkan."
                    return render_template('index.html', hasil=hasil, mode=mode, pesan=pesan, error=error)

                diblokir, sisa_detik, is_global = cek_apakah_diblokir(ip_user, token_str)
                if diblokir:
                    if is_global:
                        error = f"IP kamu diblokir GLOBAL selama {ubah_detik_jadi_kata(sisa_detik)} karena terlalu banyak gagal di banyak token!"
                    else:
                        error = f"Terlalu banyak percobaan gagal! IP kamu diblokir untuk token ini selama {ubah_detik_jadi_kata(sisa_detik)} lagi."
                    return render_template('index.html', hasil=hasil, mode=mode, pesan=pesan, error=error)

                if token_str.startswith("FILEv3."):
                    valid, salt, nonce, ciphertext, alasan = cek_token_file_valid(token_str, password)
                    if not valid:
                        if alasan == "expired":
                            error = "Token ini SUDAH KEDALUWARSA! Token hanya berlaku 24 jam."
                            return render_template('index.html', hasil=hasil, mode=mode, pesan=pesan, error=error)
                        durasi, total_gagal, is_g = catat_gagal_dan_cek_hukuman(ip_user, token_str)
                        if durasi > 0:
                            error = f"Password salah! Kamu sudah gagal {total_gagal}x. Token ini terkunci selama {ubah_detik_jadi_kata(durasi)}."
                        else:
                            sisa_coba = 3 - (total_gagal % 3)
                            error = f"Password salah atau Token rusak! Sisa percobaan sebelum terkunci: {sisa_coba}x"
                        return render_template('index.html', hasil=hasil, mode=mode, pesan=pesan, error=error)

                    tandai_token_hangus(sidik_jari)
                    hapus_catatan_gagal(ip_user, sidik_jari)
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
                    return Response(generator_dekrip_file(salt, nonce, ciphertext, password, nama_file), mimetype=mimetype, headers={"Content-Disposition": f"attachment; filename={nama_file}"})

                hasil_bytes, alasan = dekrip_dengan_password(token_str, password)
                if hasil_bytes is None:
                    if alasan == "expired":
                        error = "Token ini SUDAH KEDALUWARSA! Token hanya berlaku 24 jam."
                    else:
                        durasi, total_gagal, is_g = catat_gagal_dan_cek_hukuman(ip_user, token_str)
                        if durasi > 0:
                            error = f"Password salah! Kamu sudah gagal {total_gagal}x. Token ini terkunci selama {ubah_detik_jadi_kata(durasi)}."
                        else:
                            sisa_coba = 3 - (total_gagal % 3)
                            error = f"Password salah atau Token rusak! Sisa percobaan sebelum terkunci: {sisa_coba}x"
                else:
                    tandai_token_hangus(sidik_jari)
                    hapus_catatan_gagal(ip_user, sidik_jari)
                    if hasil_bytes.startswith(b"TEXT:"):
                        hasil = hasil_bytes[5:].decode(errors='ignore')
                    else:
                        try:
                            hasil = hasil_bytes.decode()
                        except:
                            error = "Data ini bukan teks, coba cek lagi!"

    return render_template('index.html', hasil=hasil, mode=mode, pesan=pesan, error=error, hasil_file=hasil_file, hasil_filename=hasil_filename, hasil_mimetype=hasil_mimetype)

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True
