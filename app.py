from flask import Flask, render_template , request # kullanicidan gelen veriyi okuyacagiz o yuzden request ekledik
import zxcvbn
import hashlib
from argon2 import PasswordHasher
import bcrypt
import secrets #salt iicn secret tokens lazim
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

@app.route("/encoding")
def encoding():
    return render_template("encoding.html")


#---------Open Network Subnet Planner
#----------------------------------------------------------
@app.route("/network")
def network():
    return render_template("network.html")

@app.route("/web")
def web():
    return render_template("web.html")

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