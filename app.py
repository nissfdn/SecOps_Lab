import os
import sqlite3
import base64
import hashlib
import json
import secrets
from ipaddress import ip_address

import requests
import bcrypt
import jwt
import zxcvbn

from dotenv import load_dotenv #.env ye secret keyleri ekledik
from flask import Flask, render_template, request, session, redirect ## kullanicidan gelen veriyi okuyacagiz o yuzden request ekledik
#from werkzeug.security import generate_password_hash, check_password_hash bu werkzeug iicn ama biz argon2id ile hash yaptik
from argon2 import PasswordHasher
from urllib.parse import quote, unquote  #quote urlencode unquote urldecode icin
from datetime import datetime, timezone, timedelta

load_dotenv()  #.env file a flask iicn ve jwt token icin secret keyleri kaydettim
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is not set")

FLASK_SECRET = os.environ.get("FLASK_SECRET")
if not FLASK_SECRET:
    raise RuntimeError("FLASK_SECRET environment variable is not set")


app = Flask(__name__)
app.config["SECRET_KEY"] = FLASK_SECRET
ph = PasswordHasher() #argon2 mantigi


#----------------------------------------------------------------
#----------Database fonksiyonlarini ekliyorum login icin\--------
#----------------------------------------------------------------
def init_db():
    conn = sqlite3.connect("/tmp/secops.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            status TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

def log_login(username, status, ip_address, user_agent):
    conn = sqlite3.connect("/tmp/secops.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO login_logs (username, status, ip_address, user_agent, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        username,
        status,
        ip_address,
        user_agent,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    #alanlar bos mu
    if not username or not password:
        return render_template(
            "login.html",
            error= "Username or Password are required"
        )

    #sifreyi hashle
    #password_hash = generate_password_hash(password) bu werkzeug ile hashleme
    password_hash = ph.hash(password) #bu argon2id ile hashleme

    #database e kaydet
    conn = sqlite3.connect("/tmp/secops.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            """ 
        INSERT INTO users (username, password)
        VALUES (?, ?)
        """,
            (username, password_hash)
        )
        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return render_template(
            "login.html",
            error= "Username already exists"
        )
    conn.close()

    return render_template(
        "login.html",
        success = "Registration successful. You can now login"
    )


# --------login işlemleri...
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")
    ip_address=request.remote_addr
    user_agent = request.headers.get("User_Agent")

    conn = sqlite3.connect("/tmp/secops.db")
    cursor = conn.cursor()

    cursor.execute(
        """
         SELECT id,username,password
         FROM users
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()
    conn.close()

    #kullanici bulundu ve sifre dogru
    #if user and check_password_hash(user[2], password): bu werkzeug icin
    password_correct = False #bu kisim argon2id ile hash
    if user:
        try:
            ph.verify(user[2],password)
            password_correct = True

        except Exception:
            password_correct = False
    #kullaniic bulundu ve sifre dogru
    if user and password_correct:

        session["user_id"] = user[0]
        session["username"] = user[1]
        session.permanent = True

        log_login(username, "SUCCESS", ip_address, user_agent)

        return redirect("/dashboard")

    #kullanici yok veya sifre yanlis
    log_login(username, "FAILED", ip_address, user_agent)

    return render_template(
        "login.html",
        error="Invalid username or password"
    )

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/login") #login olmayan kullniciyi engelledik biri http://127.0.0.1:5000/dashboard yazarsa dashboard a erisemicek login olmadiig icin


    return render_template(
        "dashboard.html",
    username=session["username"]
    )

@app.route("/password")
def password():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("password.html")


#------------password analizi
#----------------------------------------------

@app.route("/password/analyze", methods=["POST"])
def analyze_password():
    if "user_id" not in session:
        return redirect("/login")

    password=request.form.get("password") #HTML de name="password" yazmistik flask bu gonderilen form bilgiisni request.form ile aliyor
    zxcvbn_result=zxcvbn.zxcvbn(password)
    print(zxcvbn_result)

    length=len(password)
    uppercase=any(char.isupper() for char in password) #any fonksiyonu tum karakterleri kontrol ediyor bir tane bile varsa true doner
    lowercase=any(char.islower() for char in password)
    numbers=any(char.isdigit() for char in password)
    special=any(not char.isalnum() for char in password) #isalnum karakterleri harf mi sayi mi dye kontrol ediyor

    zxcvbn_score= zxcvbn_result["score"] #bu score zxcvbn kuutphanesine gore hesaplanan score
    if zxcvbn_score == 0:
        predictability="Very High"
    elif zxcvbn_score == 1:
        predictability="High"
    elif zxcvbn_score == 2:
        predictability="Medium"
    elif zxcvbn_score == 3:
        predictability="Low"
    elif zxcvbn_score == 4:
        predictability="Very Low"

    score = 0

    score += len(password) * 2

    if score > 30:
        score = 30

    if uppercase:
        score += 15

    if lowercase:
        score += 15

    if numbers:
        score += 15

    if special:
        score += 25

    if score < 40:
        strength = "Weak"
    elif score < 70:
        strength = "Medium"
    else:
        strength = "Strong"


    result={ #neden dictionary yaptik cunku html e tek bir paket halinde gondermek kolay
        "length":length,
        "uppercase":uppercase,
        "lowercase":lowercase,
        "numbers":numbers,
        "special":special,
        "strength":strength,
        "predictability":predictability

    }


    return render_template(
        "password.html",
        result=result
    )


#-------------pasword hashing argon2id bcrypt....
#-----------------------------------------------------

@app.route("/password/hash", methods=["GET","POST"])
def password_hashing():
    if "user_id" not in session:
        return redirect("/login")
    hashed_password=None

    if request.method == "POST":
        password = request.form.get("password")
        algorithm=request.form.get("algorithm")

        if algorithm == "argon2":
            hashed_password=ph.hash(password)  #argon2 ile hashledim

        elif algorithm == "bcrypt":
            hashed_password=bcrypt.hashpw(
                password.encode(),
                bcrypt.gensalt()
            )

        elif algorithm == "scrypt":
            salt=secrets.token_bytes(16)
            hashed_password = hashlib.scrypt(
                password.encode(), #parolayi bytes yapiyor
                salt=salt, #rastgele salt
                n=16384,      #cpu/memory maliyeti
                r=8,      #block size
                p=1,      #parallelism
            )

        elif algorithm == "pbkdf2":
            salt = secrets.token_bytes(16)
            hashed_password = hashlib.pbkdf2_hmac(
                hash_name="sha256", #sha256...
                password=password.encode(),
                salt=salt, #olsuturdugun salt
                iterations=600000, #tekrar sayisi
                dklen=32 #olusturulacak anahtarin uzunlugu
            )


    return render_template(
            "password.html",
            hashed_password=hashed_password
    )


#---------------hashing md5 sha256 ....
#-----------------------------------------------------

@app.route("/hashing", methods=["GET","POST"])
def hashing():
    if "user_id" not in session:
        return redirect("/login")

    hashed = None #bunu yazmazsak hashed sadece postta calisiyor dolayisiyla sayfayi ilk actigimda hashed henuz olusturulmamis olucak bunu onlemek icin yazdik

    if request.method == "POST":
        text=request.form.get("text") #kullanicidan hello123 falan aliyoruz
        algorithm=request.form.get("algorithm") #algoritmayi yolluyoruz

        algorithms={
            "md5":hashlib.md5, #guvenli degil cunkuu geri dondurulebilir
            "sha256":hashlib.sha256, #sha256 kullanmayiz sifrelemede cunku cok hizli hacker ayni anda bir cok saldiri denemesi yapabilir biz yavas ve maliyetli bir sifrelemee algoritmasi istiyooruz
            "sha512":hashlib.sha512,
            "sha3_256":hashlib.sha3_256,
            "sha1": hashlib.sha1
        }

        #input validation
        if algorithm not in algorithms:
            return render_template(
                "hashing.html",
                 error="Invalid algorithm"
            )

        hash_function=algorithms[algorithm] #secilen fonksiyonu degiskende tuttuk

        hashed = hash_function(text.encode()).hexdigest() #"sha256"-> algorithms["sha256"] -> hashlib.sha256 -> text.encode() -> SHA-256 -> hexdigest()-> hash
      #ama guvenlik problemi var html den istedigi seyi gonderir kullanici bu da KeyError verir bu yuzden yukarida algoritma icinde mi kontrolu yapiyoruz if algorithm not in algorithms

    return render_template(
        "hashing.html",
         hashed=hashed
    )


#-----------encoding base64.....
#------------------------------------------------------

@app.route("/encoding", methods=["GET","POST"])
def encoding():
    if "user_id" not in session:
        return redirect("/login")

    encoded = None #yani henuz encode edilmis veri yok kullanici formu gonderince None nin uzerine gercek deger yaziliyor

    if request.method == "POST":
        text=request.form.get("text") #base64 formayina donusturecegimiz text i yolluyoruz
        encoded = base64.b64encode(text.encode()).decode()
        #text kullanicinin yazdigi normal python stringi
        #base64.b64encode() string kabul etmez bytes ister bu yuzden text.encode() yaziyoruz yani string i bytes a donduruyor
        #artik elimizde bytes var biz html e bytes gondermek istemiyoruz o yuzden .decode() stringe ceviiryoruz
        print(encoded)

    return render_template(
        "encoding.html",
        encoded=encoded
    )

#-----------decoding base64.....
#------------------------------------------------------

@app.route("/encoding/decode", methods=["GET","POST"])
def encoding_decode():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        encoded_text=request.form.get("encoded_text")
        decoded=base64.b64decode(encoded_text.encode()).decode() #modul fonksiyon cagirdik
        print(decoded)

    return render_template(
        "encoding.html",
        decoded=decoded
    )

#-----------Url encoding .....
#------------------------------------------------------

@app.route("/encoding/url", methods=["POST"])
def url_encode():
    if "user_id" not in session:
        return redirect("/login")

    text=request.form.get("text")
    urlencoded = quote(text) #fonksiyonu dogrudan kullandik
    return render_template(
        "encoding.html",
        urlencoded=urlencoded
    )

#-----------Url decoding .....
#------------------------------------------------------

@app.route("/encoding/url/decode", methods=["POST"])
def url_decode():
    if "user_id" not in session:
        return redirect("/login")

    text=request.form.get("text")
    urldecoded = unquote(text) #fonksiyonu dogrudan kullandik
    return render_template(
        "encoding.html",
        urldecoded=urldecoded
    )

#-----------Hex encoding .....
#------------------------------------------------------

@app.route("/encoding/hex", methods=["POST"])
def hex_encode():
    if "user_id" not in session:
        return redirect("/login")
    text=request.form.get("text")
    hexencoded=text.encode().hex() #text i bytes a cevirme
    return render_template(
        "encoding.html",
        hexencoded=hexencoded
    )

#-----------Hex decoding .....
#------------------------------------------------------

@app.route("/encoding/hex/decode", methods=["POST"])
def hex_decode():
    if "user_id" not in session:
        return redirect("/login")

    text=request.form.get("text")
    hexdecoded=bytes.fromhex(text).decode() #bytes i text e cevirme
    return render_template(
        "encoding.html",
        hexdecoded=hexdecoded
    )

#---------Open Network Subnet Planner
#----------------------------------------------------------
@app.route("/network")
def network():
    if "user_id" not in session:
        return redirect("/login")

    return render_template("network.html")

#---------Web Analyzer----------------
#----------------------------------------------------------
@app.route("/web", methods=["GET", "POST"])
def web():
    if "user_id" not in session:
        return redirect("/login")

    headers = None #sayfa ilk acildiginda henuz http  header bilgisi olmadigi iicn none ile baslatiyoruz
    security_results = None #guvenlik headerlarinin sonuclarini tutacagimiz degiskeni baslnagicta none yapiyoruz
    target_url = None

    if request.method == "POST": #kullanici formu gonderdiginde post istegi olusur

        target_url = request.form.get("url")#html formundan gonderilen url bilgiisni aliyoruz


        response = requests.get(target_url)# kullanicinin gonderdiig url e http get istegi gonderiyoruz

        headers = dict(response.headers)#sunucunun response headerlarini aliyoruz
        #dict() ile normal Python dictionary'sine çeviriyoruz
        if "Set-Cookie" in headers:
            headers["Set-Cookie"] = "[REDACTED]" #kullanici arayuzunde cookie degerlerini gosterme

        #kontrol etmek istediigmiz guvenlik headerlarini belirliyoruz
        #key: gercek http header adi
        #value: bu headerin bizim uygulamamizdaki aciklamasi
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "Referrer-Policy": "Referrer Policy",
            "Permissions-Policy": "Permissions Policy"
        }

        #guvenlik headerlarinin sonuclarini tutacak bos dict olusturuyoruz
        security_results = {}


        #belirlediigmiz her guvenlik  heraderini tek tek kontrol ediyoruz
        for header, description in security_headers.items():

            if header in headers: #kontrol ettgiimiz header response icinde varsa
                value = headers[header]
                assessment = "Present"

                # X Frame Options icin analiz
                if header == "X-Frame-Options":
                    if value.upper() in ["DENY","SAMEORIGIN"]:
                        assessment = "Good"
                    else:
                        assessment = "Check Value"

                #HSTS analizi
                elif header == "Strict-Transport-Security":
                    value_lower=value.lower()

                    if "max-age" in value_lower:
                        max_age_part=value_lower.split("max-age=")[1].split(";")[0]
                        try:
                            max_age=int(max_age_part)
                            if max_age>=31536000:
                                assessment="Good"
                            else:
                                assessment="Weak max-age"
                        except ValueError:
                            assessment="invalid max-age"
                    else:
                        assessment="Missing max-age"

                # X-Content type options
                elif header == "X-Content-Type-Options":
                    values = [v.strip().lower() for v in value.split(",")]

                    if all(v == "nosniff" for v in values):
                        assessment = "Good"
                    else:
                        assessment = "Invalid value"


                # Content Security Policy(CSP) analizi
                elif header == "Content-Security-Policy":

                    value_lower = value.lower()

                    has_default_src = "default-src" in value_lower
                    has_script_src = "script-src" in value_lower
                    has_object_none = "object-src 'none'" in value_lower

                    if has_default_src and has_script_src and has_object_none:
                        assessment = "Good"

                    elif has_default_src and has_script_src:
                        assessment = "Present, but object-src 'none' is missing"

                    else:
                        assessment = "Weak CSP"


                #Referrer policy analizi
                elif header == "Referrer-Policy":
                    value_lower = value.lower()
                    allowed_values = [  #kabul edecegimi zdegerleri bir listeye koyuyoruz
                         "no-referrer",
                         "no-referrer-when-downgrade",
                         "same-origin",
                         "origin",
                         "strict-origin",
                         "origin-when-cross-origin",
                         "strict-origin-when-cross-origin",
                         "unsafe-url"
                    ]
                    if value_lower in allowed_values:
                        assessment = "Good"
                    else:
                        assessment = "Check Value"

                #Permissions Policy
                elif header == "Permissions-Policy":
                    value_lower = value.lower()

                    # Kullanıcı açısından hassas özelliklerin kapatılıp kapatılmadığını kontrol ediyoruz
                    protected_features = [
                        "camera=()",
                        "microphone=()",
                        "geolocation=()"
                    ]

                    # Tüm özellikler kapatılmışsa iyi bir yapılandırma olarak değerlendiriyoruz
                    if all(feature in value_lower for feature in protected_features): # buradaki all ucunun de bulunmasi gerekiyor bir tanesi bile yoksa check policy
                        assessment = "Good"

                    # Header var ama bazı özellikler açık bırakılmışsa bunu belirtiyoruz
                    else:
                        assessment = "Check policy"

                security_results[header] = {  # header in buludnuugunu status=true olarak kaydediyorz
                    "description": description,
                    "status": True,
                    "value": value,  # headerin gercek degerini aliyor
                    "assessment": assessment
                }



            else: #header response icinde bulunmuyorsa
                security_results[header] = {
                    "description": description,
                    "status": False,
                    "value": None,
                    "assessment": "Missing"
                }

    return render_template(
        "web.html",
        headers=headers,
        security_results=security_results,
        target_url=target_url
    )

#-----------------JWT token olusturma----------------------
#--------------------------------------------------

def base64url_decode(data):
    #bu yardimci fonksiyonu yazmamizin sebebi belki payload 4. kati basamak olmaz
    #bu fonksiyon sayesinde 4.un kati yapiyoruz bosluklari dolduuryor
    padding = "=" * (-len(data) % 4)

    decoded = base64.urlsafe_b64decode(
        data + padding
    )

    return decoded.decode("utf-8")
@app.route("/jwt", methods=["GET","POST"])
def jwt_tool(): #jwt yaparsan python jwt dediginde kutuphaneyi degil jwt fonksiyonunu goruyor hata veriyor
    if "user_id" not in session:
        return redirect("/login")

    token=None #none cunku sayfa ilk acildiigin jwt token olusturulmadi
    decoded_header = None
    decoded_payload = None
    signature = None
    now = datetime.now(timezone.utc)

    if request.method == "POST":
        #formdan uc bilgi aliyoruz
        username = request.form["username"]
        user_id=request.form["user_id"]
        role=request.form["role"]

        #bunlari payload a koyuyoruz
        payload={ #token in tasifiigi bilgiler
            "user_id":user_id,
            "username":username,
            "role":role,
            "iat": now,
            "exp": now + timedelta(days=7)
        }

        token = jwt.encode(
            payload,
            JWT_SECRET,
            algorithm="HS256"
        )

        #jwt yi uc parcaya ayiriryoruz payloada erismek iicn
        parts = token.split(".")

        #header payload ve signature bolumlerini aliyourz
        encoded_header = parts[0]
        encoded_payload = parts[1]
        signature = parts[2]

        #Base64URL encoded header ve payload i decode ediyoruz
        decoded_header = json.loads(base64url_decode(encoded_header))
        decoded_payload = json.loads(base64url_decode(encoded_payload))

    return render_template(
        "jwt.html",
        token=token,
        decoded_header=decoded_header,
        decoded_payload=decoded_payload,
        signature=signature
    )

#-----------------JWT token analiz etme----------------------
#--------------------------------------------------

@app.route("/jwt/analyze", methods=["POST"])
def jwt_analyze():
    if "user_id" not in session:
        return redirect("/login")

    token = request.form.get("jwt_token")

    if not token:
        return render_template(
            "jwt.html",
            jwt_error="JWT token is required"
        )

    decoded_header = None
    decoded_payload = None
    signature = None
    jwt_error = None
    verification_status = None
    claim_analysis = {}

    try:

        # JWT'yi üç parçaya ayırıyoruz
        parts = token.split(".")

        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        encoded_header = parts[0]
        encoded_payload = parts[1]
        signature = parts[2]

        # Header ve payload decode
        decoded_header = json.loads(
            base64url_decode(encoded_header)
        )

        decoded_payload = json.loads(
            base64url_decode(encoded_payload)
        )

        # Signature doğrulama
        jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )

        verification_status = True

    except jwt.InvalidSignatureError:

        verification_status = False
        jwt_error = "Invalid signature"

    except jwt.InvalidTokenError as e:

        verification_status = False
        jwt_error = f"Invalid JWT token: {str(e)}"

    except (ValueError, json.JSONDecodeError):

        jwt_error = "Invalid JWT format"


    # ==========================================
    # JWT CLAIM ANALYSIS
    # ==========================================

    # Decode işlemi başarılıysa claimleri analiz et
    if decoded_payload is not None:

        # -------------------------
        # iat
        # -------------------------

        if "iat" in decoded_payload:

            try:

                iat_time = datetime.fromtimestamp(
                    decoded_payload["iat"],
                    timezone.utc
                )

                claim_analysis["iat"] = {
                    "value": iat_time.strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    ),
                    "description": "Token creation time"
                }

            except (ValueError, TypeError, OverflowError):

                claim_analysis["iat"] = {
                    "value": "Invalid",
                    "description": "Invalid iat value",
                    "status": "Invalid"
                }


        # -------------------------
        # exp
        # -------------------------

        if "exp" in decoded_payload:

            try:

                exp_time = datetime.fromtimestamp(
                    decoded_payload["exp"],
                    timezone.utc
                )

                now = datetime.now(timezone.utc)

                if exp_time < now:
                    exp_status = "Expired"
                else:
                    exp_status = "Valid"

                claim_analysis["exp"] = {
                    "value": exp_time.strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    ),
                    "description": "Token expiry time",
                    "status": exp_status
                }

            except (ValueError, TypeError, OverflowError):

                claim_analysis["exp"] = {
                    "value": "Invalid",
                    "description": "Invalid exp value",
                    "status": "Invalid"
                }

        else:

            claim_analysis["exp"] = {
                "value": "Missing",
                "description": "Token has no expiration time",
                "status": "Missing"
            }


        # -------------------------
        # sub
        # -------------------------

        if "sub" in decoded_payload:

            claim_analysis["sub"] = {
                "value": decoded_payload["sub"],
                "description": "Token subject / user"
            }


        # -------------------------
        # iss
        # -------------------------

        if "iss" in decoded_payload:

            claim_analysis["iss"] = {
                "value": decoded_payload["iss"],
                "description": "Token issuer"
            }


        # -------------------------
        # aud
        # -------------------------

        if "aud" in decoded_payload:

            claim_analysis["aud"] = {
                "value": decoded_payload["aud"],
                "description": "Token audience"
            }


        # -------------------------
        # nbf
        # -------------------------

        if "nbf" in decoded_payload:

            try:

                nbf_time = datetime.fromtimestamp(
                    decoded_payload["nbf"],
                    timezone.utc
                )

                now = datetime.now(timezone.utc)

                if nbf_time > now:
                    nbf_status = "Not active yet"
                else:
                    nbf_status = "Active"

                claim_analysis["nbf"] = {
                    "value": nbf_time.strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    ),
                    "description": "Token activation time",
                    "status": nbf_status
                }

            except (ValueError, TypeError, OverflowError):

                claim_analysis["nbf"] = {
                    "value": "Invalid",
                    "description": "Invalid nbf value",
                    "status": "Invalid"
                }


    return render_template(
        "jwt.html",
        analyzed_token=token,
        decoded_header=decoded_header,
        decoded_payload=decoded_payload,
        signature=signature,
        verification_status=verification_status,
        jwt_error=jwt_error,
        claim_analysis=claim_analysis
    )

# -------------------------
# Login Analysis
# -------------------------
@app.route("/logs")
def logs():
    # Login olmayan kullanıcı log ekranına giremesin
    if "user_id" not in session:
        return redirect("/login")
#conn -> database    cursor -> database e komut gonderen arac
    conn = sqlite3.connect("/tmp/secops.db")
    cursor = conn.cursor() #cursor sayesinde database e sql komutlari gonderebiliyoruz

    cursor.execute(""" 
    SELECT id, username,status, ip_address, user_agent, timestamp
    FROM login_logs
    ORDER BY id DESC  --en yeni login en ustte
                   """)

    login_logs = cursor.fetchall() #fetchall() databse den gelen butun saturlari alir

    #toplam giris
    cursor.execute(""" 
    SELECT COUNT(*)
    FROM login_logs
                   """)

    total_logins = cursor.fetchone() [0]

    #basarili giris
    cursor.execute(""" 
    SELECT COUNT(*)
    FROM login_logs
    WHERE status = 'SUCCESS'
                   """)

    successful_logins = cursor.fetchone() [0]

    # basarisiz giris
    cursor.execute("""
                   SELECT COUNT(*)
                   FROM login_logs
                   WHERE status = 'FAILED'
                   """)

    failed_logins = cursor.fetchone()[0]

    # 3 veya daha fazla başarısız giriş yapan kullanıcılar supheli griis
    cursor.execute("""
                   SELECT username, COUNT(*)
                   FROM login_logs
                   WHERE status = 'FAILED'
                   GROUP BY username
                   HAVING COUNT(*) >= 3
                   """)

    suspicious_logins = cursor.fetchall()

    conn.close() #database in baglantisni kapatiyoruz

    return render_template(
        "logs.html",
         login_logs=login_logs,
        total_logins=total_logins,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        suspicious_logins=suspicious_logins
    )


init_db()

if __name__ == "__main__":
    app.run(debug=True)