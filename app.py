from flask import Flask, render_template , request # kullanicidan gelen veriyi okuyacagiz o yuzden request ekledik
import zxcvbn
import hashlib
app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/password")
def password():
    return render_template("password.html")

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

@app.route("/hashing", methods=["GET","POST"])
def hashing():

    if request.method == "POST":
        password = request.form.get("password")

        hashed = hashlib.sha256(password.encode()).hexdigest()

    return render_template(
        "hashing.html",
         hashed=hashed
    )

@app.route("/encoding")
def encoding():
    return render_template("encoding.html")

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