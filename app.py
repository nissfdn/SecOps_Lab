from flask import Flask, render_template , request # kullanicidan gelen veriyi okuyacagiz o yuzden request ekledik
import zxcvbn
import hashlib
from argon2 import PasswordHasher
import bcrypt
import secrets #salt iicn secret tokens lazim
import base64
from urllib.parse import quote,unquote  #quote=url encode--unquote=url decode icin
import requests
app = Flask(__name__)

ph = PasswordHasher() #argon2 mantigi

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/password")
def password():
    return render_template("password.html")


#------------password analizi
#----------------------------------------------

@app.route("/password/analyze", methods=["POST"])
def analyze_password():

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
    return render_template("network.html")

@app.route("/web", methods=["GET", "POST"])
def web():

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


@app.route("/jwt")
def jwt():

    return render_template("jwt.html")

@app.route("/logs")
def logs():
    return render_template("logs.html")

@app.route("/settings")
def settings():
    return render_template("settings.html")

if __name__ == "__main__":
    app.run(debug=True)