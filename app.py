import os
import random
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from flask_mail import Mail, Message
from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure forgot password
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'traveltime.amirmahditizchang@gmail.com'
app.config['MAIL_PASSWORD'] = 'TravelTime@CS50x-2023.FinalProject/Amirmahdi-Tizchang'

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///DATABASE.db")

# Open Gmail to send a temporary password for the users who have forgotten their password
mail = Mail(app)

# List of [dangers password]
CYBERSECURITY = [
    "123456",
    "123456789",
    "12345",
    "qwerty",
    "password",
    "12345678",
    "11111",
    "123123",
    "1234567890",
    "1234567"
]

# List of types of trips
TYPES = [
    "Romantic",
    "Recreational",
    "Historical",
    "Cultural",
    "Historic",
    "Beach"
]

# List of countries include in DATABASE.db
COUNTRIES = [
    "France",
    "United States",
    "United Kingdom",
    "Japan",
    "Italy",
    "Spain",
    "Australia",
    "Germany",
    "Netherlands",
    "China",
    "Austria",
    "United Arab Emirates",
    "Morocco",
    "Singapore",
    "Poland",
    "Canada",
    "Brazil",
    "India",
    "Thailand",
    "Czech Republic",
    "South Africa",
    "Ireland",
    "Hungary",
    "Turkey",
    "Russia",
    "Iran",
]

# List of countries include in DATABASE.db
CONTINENTS = [
    "Europe",
    "North America",
    "Asia",
    "Australia",
    "Africa",
    "South America",
    "Asia/Europe"
]


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure email was submitted
        if not request.form.get("email"):
            return apology("must provide email", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE email = ?", request.form.get("email"))

        # Ensure Account exists
        if len(rows) != 1:
            return render_template('log-in.html', value_email="is-invalid")

        # Ensure password is correct
        elif not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template('log-in.html', value_password="is-invalid")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Message for taking actions
        messages = ["You are loged in.", "success", "egiwmiit"]

        #log-in successfully
        flash(messages)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("log-in.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/reset", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":

        # Save user's inputs
        email = request.form.get("email")

        # Query database for username
        try:
            rows = db.execute("SELECT username FROM users WHERE email = ?", email)

        except ValueError:
            return render_template('reset.password.html')

        # Check if the email exists in the database
        if len(rows) != 1:
            return render_template('reset.password.html', value_email="is-invalid")

        # Generate a new random password
        new_password = str(random.randint(100000, 999999))

        # Update the user's password in the database
        db.execute("UPDATE users SET hash = ? WHERE username = ?", generate_password_hash(new_password), rows[0]['username'])

        # Send an email to the user with the new password
        msg = Message('Password Reset', sender='TravelTime.AmirmahdiTizchang@gmail.com', recipients=['email'])
        msg.body = f'''
        Hi {rows[0]['username']}!
        Your password has just been reset, don't let others read that email includes you new and temporary password.
        Your new password is: {new_password}
        Please send feedback, I will be happy if you let me know your advices or suggests through this email address.
        -Good luck
        Travel Time
        '''
        mail.send(msg)

        # Message for taking actions
        messages = ["Your password has just been reset, don't access to other people read the email!", "warning", "wdqztrtx"]

        # Let user know about bad quality of safety
        flash(messages)

        # Go back to log in page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template('reset.password.html')


@app.route("/signup", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save user input
        username = request.form.get("username")
        name = request.form.get("firstname")
        family = request.form.get("lastname")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Username is empty
        if not username:
            return apology("must provide username!", 400)

        # email is empty
        elif not email:
            return apology("must provide email!", 400)

        # Hasn't password already entered
        elif not password or not confirmation:
            return apology("must provide password and/or confirmation", 400)

        # Hasn't password already entered
        elif not family or not name:
            return apology("must provide family and/or name", 400)

        # If password doesn't match with repeated
        elif password != confirmation:
            return render_template('sign-up.html', value_password="is-invalid")

        # Check for repeated email address (user -> TABLE)
        emails = db.execute("SELECT id FROM users WHERE email = ?", email)

        if not emails:

            # Check for repeated username
            try:

                # Insert new account (user -> TABLE)
                rows = db.execute("INSERT INTO users (username, name, family, hash, email) VALUES(?, ?, ?, ?, ?)", username, name, family, generate_password_hash(password), email)

                # Login
                session["user_id"] = rows

                # Test the password the user choose
                if password not in CYBERSECURITY and any(char in password for char in ['.', '!', '@', '#', '_', '-', '/', '*', '&']) and any(char in password for char in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']) and any(char.isupper() for char in password) and any(char.islower() for char in password) and len(password) > 6:

                    # Message for taking actions
                    messages = ["Congratulations, Welcome To Travel Time.", "success", "egiwmiit"]

                    # Send it to user
                    flash(messages)

                    # Come back to home-page
                    return redirect("/")

                else:

                    # Message for taking actions
                    messages = ["Change your password, it is not safe enough to protect your account.", "danger", "bmnlikjh"]

                    # Send it to user
                    flash(messages)

                    # Come back to home-page
                    return redirect("/")

            except:
                return render_template('sign-up.html', value_username="is-invalid")

        else:

            # Show erorr to user
            return render_template('sign-up.html', value_email="is-invalid")


    # Show the register form.method = "GET"
    return render_template("sign-up.html")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save user input
        password = request.form.get("password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Hasn't password already entered
        if not password:
            return apology("must provide password", 400)

        # Hasn't password already entered
        elif not new_password or not confirmation:
            return apology("must provide the new password and/or the confirmation", 400)

        # Check the old password, it should be correct
        hash = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"]

        if not check_password_hash(hash, password):
            return render_template('change.password.html', value_old="is-invalid")

        # If new_password doesn't match with repeated
        elif new_password != confirmation:
            return render_template('change.password.html', value_new="is-invalid")

        try:
            # Updata new account (user -> info)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_password), session["user_id"])

        # If something happens which wasn't excepted
        except:
            return apology("Something went wrong please try again", 400)

        # Test the password the user choose
        if new_password not in CYBERSECURITY and any(char in new_password for char in ['.', '!', '@', '#', '_', '-', '/', '*', '&']) and any(char in new_password for char in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']) and any(char.isupper() for char in new_password) and any(char.islower() for char in new_password) and len(new_password) > 6:

            # Message for taking actions
            messages = ["Great choice ,your password has changed successfully!", "success", "egiwmiit"]

            # Send it to user
            flash(messages)

            # Come back to home-page
            return redirect("/")

        else:

            # Message for taking actions
            messages = ["The password you have choosen is not strength enough to protect your informations.", "danger", "bmnlikjh"]

            # Send it to user
            flash(messages)

            # Come back to home-page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("change.password.html")


@app.route("/change-email", methods=["GET", "POST"])
@login_required
def change_email():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save user input
        password = request.form.get("password")
        email = request.form.get("email")

        # Check the password, it should be correct
        hash = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"]

        if not check_password_hash(hash, password):
            return render_template('change.email.html', value_password="is-invalid")

        # Hasn't username already entered
        elif not email:
            return apology("must provide your new email", 400)

        # Hasn't password already entered
        elif not password:
            return apology("must provide password", 400)

        # Check for repeated email address
        try:

            # Updata new account (user -> info)
            db.execute("UPDATE users SET email = ? WHERE id = ?", email, session["user_id"])
            # Message for taking actions
            messages = ["Your email address updated.", "success", "egiwmiit"]

            # Send it to user
            flash(messages)

            # Set a query on user information
            info = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]

            # Go to user page
            return render_template("user.html", info=info)

        # If email address has already taken
        except:

            # Repeated email address
            return render_template('change.email.html', value_email="is-invalid")

    # User reached route via GET (as by clicking a link or via redirect)
    else:

        return render_template("change.email.html")


@app.route("/change-username", methods=["GET", "POST"])
@login_required
def change_username():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save user input
        username = request.form.get("username")
        password = request.form.get("password")

        # Check the password, it should be correct
        hash = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"]

        if not check_password_hash(hash, password):
            return render_template('change.username.html', value_password="is-invalid")

        # Hasn't username already entered
        elif not username:
            return apology("must provide your new username", 400)

        # Hasn't password already entered
        elif not password:
            return apology("must provide password", 400)

        # Check for repeated username (user -> TABLE)
        try:
            # Updata new account (user -> info)
            db.execute("UPDATE users SET username = ? WHERE id = ?", username, session["user_id"])

            # Message for taking actions
            messages = ["NULL", "success", "egiwmiit"]
            messages[0] = f"hi {username}, Your username updated to the new one."

            # Send it to user
            flash(messages)

            # Set a query on user information
            info = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]

            # Go to user page
            return render_template("user.html", info=info)

        # When username is repeated
        except:

            # Repeated email address
            return render_template('change.username.html', value_username="is-invalid")

    # User reached route via GET (as by clicking a link or via redirect)
    else:

        # Show the register form. method = "POST"
        return render_template("change.username.html")


@app.route("/change-bio", methods=["GET", "POST"])
@login_required
def change_bio():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save user input
        bio = request.form.get("bio")

        # Updata new account (user -> info)
        db.execute("UPDATE users SET bio = ? WHERE id = ?", bio, session["user_id"])

        # Message for taking actions
        messages = ["Your bio changed, now others can get to know you better!", "success", "egiwmiit"]

        # Send it to user
        flash(messages)

        # Set a query on user information
        info = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]

        # Come back to home-page
        return render_template("user.html", info=info)


    # User reached route via GET (as by clicking a link or via redirect)
    else:

        # Set a query to bring user's bio to help them change it to a better one!
        blog = db.execute("SELECT bio FROM users WHERE id = ?", session["user_id"])

        # Show the register form. method = "POST"
        return render_template("change.bio.html", bio=blog)


@app.route("/remove", methods=["GET", "POST"])
@login_required
def remove_account():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save user input
        password = request.form.get("password")

        # Check the password, it should be correct
        hash = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"]

        # Hasn't password already entered
        if not password:
            return apology("must provide password", 400)

        elif not check_password_hash(hash, password):
            return render_template('remove.account.html', value_password="is-invalid")

        # Remove all user's bookmarked experiences (bookmarked_experiences -> table)
        db.execute("DELETE FROM bookmarked_experiences WHERE user_id = ?", session["user_id"])

        # Remove all bookmarked vacations (bookmarked_vacations -> table)
        db.execute("DELETE FROM bookmarked_vacations WHERE user_id = ?", session["user_id"])

        # Remove all vacations the user has liked (bookmarked_vacations -> table)
        db.execute("DELETE FROM vacation_likes WHERE user_id = ?", session["user_id"])

        # Remove all bookmarked rxperience the user has liked (bookmarked_vacations -> table)
        db.execute("DELETE FROM experience_likes WHERE user_id = ?", session["user_id"])

        # Remove all experiences the user has shared with others (experiences -> table)
        db.execute("DELETE FROM experiences WHERE user_id = ?", session["user_id"])

        # Remove the account from (user -> table)
        db.execute("DELETE FROM users WHERE id = ?", session["user_id"])

        # Forget any user_id
        session.clear()

        # Redirect user to login form
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:

        # Message for taking actions
        messages = ["Are you sure you want to delete your account and all associated data?", "info", "ncxoarcp"]

        # Send it to user
        flash(messages)

        return render_template("remove.account.html")


@app.route("/")
@login_required
def index():

    # Redirect user to about page
    return redirect("/about")


@app.route("/about",)
@login_required
def about():

    # Show the about page
    return render_template("about.html")


@app.route("/vacations")
@login_required
def vacations():

    # Set a query on whole of the liked vacations by filtering user_id and Bring all informations about evey vacations also Calcute each vaction count of likes to show
    vacations = db.execute('''
    SELECT vacations.id, vacations.city, vacations.country, vacations.continent, vacations.description, vacations.image_url,
    SUM(CASE WHEN vacation_likes.liked = 1 THEN 1 ELSE 0 END) AS like_count,
    COUNT(CASE WHEN vacation_likes.user_id = ? THEN vacation_likes.vacation_id ELSE NULL END) AS liked,
    COUNT(CASE WHEN bookmarked_vacations.user_id = ? THEN bookmarked_vacations.vacation_id ELSE NULL END) AS bookmarked
    FROM vacations
    LEFT JOIN vacation_likes ON vacations.id = vacation_likes.vacation_id
    LEFT JOIN bookmarked_vacations ON vacations.id = bookmarked_vacations.vacation_id
    GROUP BY vacations.id
    ''', session["user_id"], session["user_id"])


    # Send it to the Front-end to show
    return render_template("vacations.html", vacations=vacations, countries=COUNTRIES, types=TYPES,  continents=CONTINENTS, bool=bool, int=int)


@app.route("/info", methods=["GET", "POST"])
@login_required
def more_informations():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save id vacation to set a query
        id = request.form.get("id")

        # Check the vacation id is valid
        row = db.execute("SELECT city FROM vacations WHERE id = ?", id)

        if len(row) != 1:

            # Let the user know
            return apology("invalid vacation id!", "400")

        # Set a query on whole of the liked vacations by filtering user_id and Bring all informations about evey vacation also Calcute each vactions count of likes to show
        vacation = db.execute('''
        SELECT vacations.id, vacations.city, vacations.country, vacations.continent, vacations.description, vacations.image_url, vacations.weather, vacations.attractions, vacations.type, vacations.activities, vacations.attractions, vacations.weather, vacations.famous_foods, vacations.local_cuisine,
        SUM(CASE WHEN vacation_likes.liked = 1 THEN 1 ELSE 0 END) AS like_count,
        COUNT(CASE WHEN vacation_likes.user_id = ?  AND vacation_likes.vacation_id = ? THEN vacation_likes.vacation_id ELSE NULL END) AS liked,
        COUNT(CASE WHEN bookmarked_vacations.user_id = ? AND bookmarked_vacations.vacation_id = ? THEN bookmarked_vacations.vacation_id ELSE NULL END) AS bookmarked
        FROM vacations
        LEFT JOIN vacation_likes ON vacations.id = vacation_likes.vacation_id
        LEFT JOIN bookmarked_vacations ON vacations.id = bookmarked_vacations.vacation_id
        WHERE vacations.id = ?
        GROUP BY vacations.id
        LIMIT 1
        ''', session["user_id"], id, session["user_id"], id, id)[0]

        # Send it to the Front-end to show
        return render_template("info.html", vacation=vacation, bool=bool, int=int)

    else:

        return redirect("/vacations")


@app.route("/filter", methods=["GET", "POST"])
@login_required
def filter():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save user's filter conditions
        type = request.form.get("type")
        country = request.form.get("country")
        continent = request.form.get("continent")
        sort = request.form.get("sort-by")
        placeholders = []

        # Set the query and conditions

        query = '''
        SELECT vacations.*,
        SUM(CASE WHEN vacation_likes.liked = 1 THEN 1 ELSE 0 END) AS like_count,
        COUNT(CASE WHEN vacation_likes.user_id = ? THEN vacation_likes.vacation_id ELSE NULL END) AS liked,
        COUNT(CASE WHEN bookmarked_vacations.user_id = ? THEN bookmarked_vacations.vacation_id ELSE NULL END) AS bookmarked
        FROM vacations
        LEFT JOIN vacation_likes ON vacations.id = vacation_likes.vacation_id
        LEFT JOIN bookmarked_vacations ON vacations.id = bookmarked_vacations.vacation_id
        WHERE 1=1'''

        # Check for type condition
        if type is not None and type in TYPES:

            # Add the type condition
            query += " AND vacations.type = ?"

            # Add the type value to the placeholders list
            placeholders.append(type)

        # Check for country condition
        if country is not None and country in COUNTRIES:

            # Set the country condition
            query += " AND vacations.country = ?"

            # Add the country value to the placeholders list
            placeholders.append(country)

        # Check for continent condition
        if continent is not None and continent in CONTINENTS:

            # Set the continent condition
            query += " AND vacations.continent = ?"

            # Add the country value to the placeholders list
            placeholders.append(continent)

        # Input a part of query
        query += " GROUP BY vacations.id"



        # Check for sort condition
        if sort is not None:

            if sort == "za":

                # Set the DESC condition
                query += " ORDER BY vacations.city DESC"

            elif sort == "az":

                # Set the ASC condition
                query += " ORDER BY vacations.city ASC"

            # Check for famous vacations filter
            elif sort == "famous-vacation":

                # Set the more famous ones condition
                query += " ORDER BY like_count DESC"

            else:

                # Invalid sort value
                return apology("invalid sort value", 400)

        if not placeholders:

            # Set the query on database but without because the placeholders[] is NULL
            filter = db.execute(query, session["user_id"], session["user_id"])

        else:

            # Set the query on database
            filter = db.execute(query, session["user_id"], session["user_id"], *placeholders)

        return render_template("vacations.html", vacations=filter, countries=COUNTRIES, types=TYPES,  continents=CONTINENTS, bool=bool, int=int)

    else:
        return redirect("/vacations")


@app.route("/vacation_like", methods=["GET", "POST"])
@login_required
def like():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        id = request.form.get("id")

        # Check the vacation id is valid
        row = db.execute("SELECT city FROM vacations WHERE id = ?", id)

        if len(row) != 1:

            # Let the user know
            return apology("invalid vacation id!", "400")

        liked = db.execute("SELECT liked FROM vacation_likes WHERE user_id = ? AND vacation_id = ?", session["user_id"], id)

        if len(liked) == 1 :

            liked = bool(int(liked[0]["liked"]))

            # Check for right id and it hasn't liked before
            if liked is False:

                # Updata count of likes
                db.execute("UPDATE vacation_likes SET liked = ? WHERE user_id = ? AND vacation_id = ?", 1, session["user_id"], id)

                # Come back to vacations page
                return redirect("/vacations")

            # Check for right id
            elif liked is True:

                # Updata count of likes
                db.execute("DELETE FROM vacation_likes WHERE user_id = ? AND vacation_id = ? ", session["user_id"], id)

                # Come back to vacations page
                return redirect("/vacations")

        # For First time it should be like action
        db.execute("INSERT INTO vacation_likes (vacation_id, user_id, liked) VALUES (?, ?, ?)", id, session["user_id"], 1)

        # Come back to vacations page
        return redirect("/vacations")

    else:
        return redirect("/vacations")


@app.route("/vacation_bookmark", methods=["GET", "POST"])
@login_required
def bookmark():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        id = request.form.get("id")

        # Check the vacation id is valid
        row = db.execute("SELECT city FROM vacations WHERE id = ?", id)

        if len(row) != 1:

            # Let the user know
            return apology("invalid vacation id!", "400")

        bookmarked = db.execute("SELECT bookmarked FROM bookmarked_vacations WHERE user_id = ? AND vacation_id = ?", session["user_id"], id)

        if len(bookmarked) == 1 :

            bookmarked = bool(int(bookmarked[0]["bookmarked"]))

            # Check for right id and it hasn't bookmarked before
            if bookmarked is False:

                # Updata count of likes
                db.execute("UPDATE bookmarked_vacations SET bookmarked = ? WHERE user_id = ? AND vacation_id = ?", 1, session["user_id"], id)

                # Come back to vacations page
                return redirect("/vacations")

            # Check for right id
            elif bookmarked is True:

                # Updata count of bookmarked
                db.execute("DELETE FROM bookmarked_vacations WHERE user_id = ? AND vacation_id = ? ", session["user_id"], id)

                # Come back to vacations page
                return redirect("/vacations")


        # For First time it should be like action
        db.execute("INSERT INTO bookmarked_vacations (user_id, vacation_id, bookmarked) VALUES (?, ?, ?)", session["user_id"], id, 1)

        # Come back to vacations page
        return redirect("/vacations")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return redirect("/vacations")


@app.route("/reviews")
@login_required
def reviews():

    # Set a query on whole of the liked review by filtering user_id and Bring all informations about evey reviews also Calcute each review cpount of likes to show
    experiences = db.execute('''
    SELECT experiences.id, experiences.user_id, experiences.vacation_id, experiences.title, experiences.recommend, experiences.content, experiences.time,
    SUM(CASE WHEN experience_likes.liked = 1 THEN 1 ELSE 0 END) AS like_count,
    COUNT(CASE WHEN experience_likes.user_id = ? THEN experience_likes.experience_id ELSE NULL END) AS liked,
    COUNT(CASE WHEN bookmarked_experiences.user_id = ? THEN bookmarked_experiences.experience_id ELSE NULL END) AS bookmarked,
    vacations.city, vacations.country, vacations.continent, users.username, users.email
    FROM experiences
    LEFT JOIN experience_likes ON experiences.id = experience_likes.experience_id
    LEFT JOIN bookmarked_experiences ON experiences.id = bookmarked_experiences.experience_id
    LEFT JOIN vacations ON experiences.vacation_id = vacations.id
    LEFT JOIN users ON experiences.user_id = users.id
    GROUP BY experiences.id
    ''', session["user_id"], session["user_id"])

    # Set a query on vacations table city filed
    cities = db.execute("SELECT city FROM vacations")

    return render_template("reviews.html", experiences=experiences, bool=bool, int=int, cities=cities)


@app.route("/share", methods=["GET", "POST"])
@login_required
def sharing_Experience():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save users inputs
        title = request.form.get("title")
        content = request.form.get("content")
        recommend = request.form.get("recommend")

        # Check for valid city names
        id = db.execute("SELECT id FROM vacations WHERE city = ?", request.form.get("city"))

        if len(id) != 1:

            # Let the users know about wrong city name
            return apology("invalid city name", 400)

        else:

            try:

                db.execute("INSERT INTO experiences (user_id, vacation_id, title, content, recommend) VALUES (?, ?, ?, ?, ?)", session["user_id"], id[0]["id"], title, content, recommend)

                # Message for taking actions
                messages = ["Your experiences shared with others.", "success", "egiwmiit"]

                # Send it to user
                flash(messages)

                # Come back to home-page
                return redirect("/reviews")

            except:

                # Let the users know about wrong input
                return apology("something went wrong, please try again!", 400)


    # User reached route via GET (as by clicking a link or via redirect)
    else:

        # Set a query on vacations table city filed
        cities = db.execute("SELECT city FROM vacations")

        # Show the users review form
        return render_template("share.html", cities=cities)


@app.route("/filter_reviews", methods=["GET", "POST"])
@login_required
def filter_reviews():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save user's filter conditions
        city = request.form.get("city")
        recommend = request.form.get("recommend")
        sort = request.form.get("sort-by")
        placeholders = []

        # Set the query and conditions

        query = '''
        SELECT experiences.id, experiences.user_id, experiences.vacation_id, experiences.title, experiences.recommend, experiences.content, experiences.time,
        SUM(CASE WHEN experience_likes.liked = 1 THEN 1 ELSE 0 END) AS like_count,
        COUNT(CASE WHEN experience_likes.user_id = ? THEN experience_likes.experience_id ELSE NULL END) AS liked,
        COUNT(CASE WHEN bookmarked_experiences.user_id = ? THEN bookmarked_experiences.experience_id ELSE NULL END) AS bookmarked,
        vacations.city, vacations.country, vacations.continent, users.username, users.email
        FROM experiences
        LEFT JOIN experience_likes ON experiences.id = experience_likes.experience_id
        LEFT JOIN bookmarked_experiences ON experiences.id = bookmarked_experiences.experience_id
        LEFT JOIN vacations ON experiences.vacation_id = vacations.id
        LEFT JOIN users ON experiences.user_id = users.id
        WHERE 1=1'''

        cities = db.execute("SELECT * FROM vacations")

        check = db.execute("SELECT id FROM vacations WHERE city = ?", city)

        # Check for city condition
        if city is not None and len(check) == 1:

            # Add the city condition
            query += " AND vacations.city = ?"

            # Add the city value to the placeholders list
            placeholders.append(city)

        # Check for recommend condition
        if recommend is not None:
            if bool(int(recommend)) is True or  bool(int(recommend)) is False:

                # Set the recommend condition
                query += " AND experiences.recommend = ?"

                # Add the recommend value to the placeholders list
                placeholders.append(f"{ bool(int(recommend)) }")

        # Input a part of query
        query += " GROUP BY experiences.id"

        # Check for sort condition
        if sort is not None:

            # Check for newest reviews
            if sort == "new":

                # Set the ASC condition
                query += " ORDER BY experiences.time DESC"

            # Check for famous vacations filter
            elif sort == "famous-reviews":

                # Set the more famous ones condition
                query += " ORDER BY like_count DESC"

            else:

                # Invalid sort value
                return apology("invalid sort value", 400)

        if not placeholders:

            # Set the query on database but without because the placeholders[] is NULL
            filter = db.execute(query, session["user_id"], session["user_id"])

        else:

            # Set the query on database
            filter = db.execute(query, session["user_id"], session["user_id"], *placeholders)

        return render_template("reviews.html", experiences=filter,  cities=cities, bool=bool, int=int)

    else:
        return redirect("/reviews")


@app.route("/experience_like", methods=["GET", "POST"])
@login_required
def experience_like():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save users inputs
        id = request.form.get("id")

        # Check the vacation id is valid
        row = db.execute("SELECT * FROM experiences WHERE id = ?", id)

        if len(row) != 1:

            # Let the user know
            return apology("invalid vacation id!", "400")

        liked = db.execute("SELECT liked FROM experience_likes WHERE user_id = ? AND experience_id = ?", session["user_id"], id)

        if len(liked) == 1 :

            liked = bool(int(liked[0]["liked"]))

            # Check for right id and it hasn't liked before
            if liked is False:

                # Updata count of likes
                db.execute("UPDATE experience_likes SET liked = ? WHERE user_id = ? AND experience_id = ?", 1, session["user_id"], id)

                # Come back to vacations page
                return redirect("/reviews")

            # Check for right id
            elif liked is True:

                # Updata count of likes
                db.execute("DELETE FROM experience_likes WHERE user_id = ? AND experience_id = ? ", session["user_id"], id)

                # Come back to vacations page
                return redirect("/reviews")

        # For First time it should be like action
        db.execute("INSERT INTO experience_likes (experience_id, user_id, liked) VALUES (?, ?, ?)", id, session["user_id"], 1)

        # Come back to vacations page
        return redirect("/reviews")

    else:
        return redirect("/reviews")


@app.route("/bookmarked_experience", methods=["GET", "POST"])
@login_required
def bookmark_experiences():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save users inputs
        id = request.form.get("id")

        # Check the vacation id is valid
        row = db.execute("SELECT * FROM experiences WHERE id = ?", id)

        if len(row) != 1:

            # Let the user know
            return apology("invalid vacation id!", "400")

        bookmarked = db.execute("SELECT bookmarked FROM bookmarked_experiences WHERE user_id = ? AND experience_id = ?", session["user_id"], id)

        if len(bookmarked) == 1 :

            bookmarked = bool(int(bookmarked[0]["bookmarked"]))

            # Check for right id and it hasn't bookmarked before
            if bookmarked is False:

                # Updata count of likes
                db.execute("UPDATE bookmarked_experiences SET bookmarked = ? WHERE user_id = ? AND experience_id = ?", 1, session["user_id"], id)

                # Come back to vacations page
                return redirect("/reviews")

            # Check for right id
            elif bookmarked is True:

                # Updata count of bookmarked
                db.execute("DELETE FROM bookmarked_experiences WHERE user_id = ? AND experience_id = ? ", session["user_id"], id)

                # Come back to vacations page
                return redirect("/reviews")


        # For First time it should be like action
        db.execute("INSERT INTO bookmarked_experiences (user_id, experience_id, bookmarked) VALUES (?, ?, ?)", session["user_id"], id, 1)

        # Come back to vacations page
        return redirect("/reviews")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return redirect("/reviws")


@app.route("/bookmarked-vacations")
@login_required
def bookmarked_vacations():

    # Set a query on user's vacations bookmarked
    vacations = db.execute('''
    SELECT vacations.id, vacations.city, vacations.country, vacations.continent, vacations.description, vacations.image_url,
    SUM(CASE WHEN vacation_likes.liked = 1 THEN 1 ELSE 0 END) AS like_count,
    COUNT(CASE WHEN vacation_likes.user_id = ? THEN vacation_likes.vacation_id ELSE NULL END) AS liked,
    COUNT(CASE WHEN bookmarked_vacations.user_id = ? THEN bookmarked_vacations.vacation_id ELSE NULL END) AS bookmarked
    FROM vacations
    LEFT JOIN vacation_likes ON vacations.id = vacation_likes.vacation_id
    LEFT JOIN bookmarked_vacations ON vacations.id = bookmarked_vacations.vacation_id
    WHERE vacations.id IN (SELECT vacation_id FROM bookmarked_vacations WHERE user_id = ?)
    GROUP BY vacations.id
    ''', session["user_id"], session["user_id"], session["user_id"])

    return render_template("bookmarked.vacations.html", vacations=vacations, bool=bool, int=int)


@app.route("/bookmarked-reviews")
@login_required
def bookmarked_experiences():

    # Set a query on whole of the liked vacation by filtering user_id and Bring all informations about evey vacation also Calcute each vaction cpount of likes to show
    experiences = db.execute('''
    SELECT experiences.id, experiences.user_id, experiences.vacation_id, experiences.title, experiences.recommend, experiences.content, experiences.time,
    SUM(CASE WHEN experience_likes.liked = 1 THEN 1 ELSE 0 END) AS like_count,
    COUNT(CASE WHEN experience_likes.user_id = ? THEN experience_likes.experience_id ELSE NULL END) AS liked,
    COUNT(CASE WHEN bookmarked_experiences.user_id = ? THEN bookmarked_experiences.experience_id ELSE NULL END) AS bookmarked,
    vacations.city, vacations.country, vacations.continent, users.username, users.email
    FROM experiences
    LEFT JOIN experience_likes ON experiences.id = experience_likes.experience_id
    LEFT JOIN bookmarked_experiences ON experiences.id = bookmarked_experiences.experience_id
    LEFT JOIN vacations ON experiences.vacation_id = vacations.id
    LEFT JOIN users ON experiences.user_id = users.id
    WHERE experiences.id IN (SELECT experience_id FROM bookmarked_experiences WHERE user_id = ?)
    GROUP BY experiences.id
    ''', session["user_id"], session["user_id"], session["user_id"])

    return render_template("bookmarked.reviews.html", experiences=experiences, bool=bool, int=int)


@app.route("/my-experiences", methods=["GET", "POST"])
@login_required
def my_experiences():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Save user's inputs
        remove = request.form.get("remove")
        new = request.form.get("new")
        id = request.form.get("id")


        try:

            if remove is not None:

                # Remove the choosen experiences and delete in other table where is a foreign key
                db.execute("DELETE FROM bookmarked_experiences WHERE experience_id = ?", remove)
                db.execute("DELETE FROM experience_likes WHERE experience_id = ?", remove)

                # Remove the choosen experiences
                db.execute("DELETE FROM experiences WHERE user_id = ? AND id = ?", session["user_id"], remove)
                # Message for taking actions
                messages = ["NULL", "success", "jmkrnisz"]
                messages[0] = f"Your {remove}th shared experience completely removed."

                # Send it to user
                flash(messages)

                return redirect("/my-experiences")

            # Editing experiences they've shared
            else:

                # Edit the choosen experiences
                db.execute("UPDATE experiences SET content = ? WHERE id = ?", new, id)

                # Message for taking actions
                messages = ["Editing completed.", "success", "egiwmiit"]

                # Send it to user
                flash(messages)

                return redirect("/my-experiences")


        except:

            # Something went wrong
            return apology("something went wrong, please try again!", 400)


    # User reached route via GET (as by clicking a link or via redirect)
    else:

        # Set a query on whole of the liked vacation by filtering user_id and Bring all informations about evey vacation also Calcute each vaction cpount of likes to show
        experiences = db.execute('''
            SELECT experiences.*, vacations.city
            FROM experiences
            JOIN vacations ON experiences.vacation_id = vacations.id
            WHERE user_id = ?
            GROUP BY experiences.id''', session["user_id"])

        return render_template("my.experiences.html", experiences=experiences)


@app.route("/search")
@login_required
def search():

    # Save the word that searched
    search = request.args.get("q")

    # Save all id in a list

    vacations_id_list = []
    experiences_id_list = []

    # Set two queries on two table experiences and vacations

    # Vacations' query
    vacations_id = db.execute("""
    SELECT id FROM vacations WHERE
    city LIKE '%' || ? || '%' OR
    country LIKE '%' || ? || '%' OR
    continent LIKE '%' || ? || '%' OR
    description LIKE '%' || ? || '%' OR
    type LIKE '%' || ? || '%' OR
    activities LIKE '%' || ? || '%' OR
    attractions LIKE '%' || ? || '%' OR
    weather LIKE '%' || ? || '%' OR
    famous_foods LIKE '%' || ? || '%' OR
    local_cuisine LIKE '%' || ? || '%'
    """, search, search, search, search, search, search, search, search, search, search)

    # EXperiences' query
    experiences_id = db.execute("""
    SELECT experiences.id FROM experiences
    INNER JOIN vacations ON experiences.vacation_id = vacations.id
    JOIN users ON experiences.user_id = users.id
    WHERE experiences.title LIKE '%' || ? || '%' OR
    vacations.city LIKE '%' || ? || '%' OR
    vacations.country LIKE '%' || ? || '%' OR
    vacations.continent LIKE '%' || ? || '%' OR
    vacations.type LIKE '%' || ? || '%' OR
    users.username LIKE '%' || ? || '%' OR
    users.family LIKE '%' || ? || '%' OR
    users.name LIKE '%' || ? || '%' OR
    users.email LIKE '%' || ? || '%' OR
    experiences.content LIKE '%' || ? || '%'
    """, search, search, search, search, search, search, search, search, search, search)

    for experience in experiences_id:
        experiences_id_list.append(experience["id"])

    for vacations in vacations_id:
        vacations_id_list.append(vacations["id"])

    # Set a query on whole of the liked reviews by filtering user_id and Bring all informations about evey reviews also Calcute each review count of likes to show
    experiences = db.execute('''
    SELECT experiences.id, experiences.user_id, experiences.vacation_id, experiences.title, experiences.recommend, experiences.content, experiences.time,
    SUM(CASE WHEN experience_likes.liked = 1 THEN 1 ELSE 0 END) AS like_count,
    COUNT(CASE WHEN experience_likes.user_id = ? THEN experience_likes.experience_id ELSE NULL END) AS liked,
    COUNT(CASE WHEN bookmarked_experiences.user_id = ? THEN bookmarked_experiences.experience_id ELSE NULL END) AS bookmarked,
    vacations.city, vacations.country, vacations.continent, users.username, users.email
    FROM experiences
    LEFT JOIN experience_likes ON experiences.id = experience_likes.experience_id
    LEFT JOIN bookmarked_experiences ON experiences.id = bookmarked_experiences.experience_id
    LEFT JOIN vacations ON experiences.vacation_id = vacations.id
    LEFT JOIN users ON experiences.user_id = users.id
    WHERE experiences.id IN (?)
    GROUP BY experiences.id
    ''', session["user_id"], session["user_id"], experiences_id_list)

    # Set a query on whole of the liked vacations by filtering user_id and Bring all informations about evey vacations also Calcute each vaction count of likes to show
    vacations = db.execute('''
    SELECT vacations.id, vacations.city, vacations.country, vacations.continent, vacations.description, vacations.image_url,
    SUM(CASE WHEN vacation_likes.liked = 1 THEN 1 ELSE 0 END) AS like_count,
    COUNT(CASE WHEN vacation_likes.user_id = ? THEN vacation_likes.vacation_id ELSE NULL END) AS liked,
    COUNT(CASE WHEN bookmarked_vacations.user_id = ? THEN bookmarked_vacations.vacation_id ELSE NULL END) AS bookmarked
    FROM vacations
    LEFT JOIN vacation_likes ON vacations.id = vacation_likes.vacation_id
    LEFT JOIN bookmarked_vacations ON vacations.id = bookmarked_vacations.vacation_id
    WHERE vacations.id IN (?)
    GROUP BY vacations.id
    ''', session["user_id"], session["user_id"], vacations_id_list)

    return render_template("search.html", vacations=vacations, experiences=experiences, bool=bool, int=int)


@app.route("/user")
@login_required
def user():

    # Save user ID and check it for make sure the id is true
    id = request.args.get("id")

    try:
        # Set a query to select all user information except [hash, id]
        info = db.execute("SELECT username, name, family, email, bio FROM users WHERE id = ?", id)[0]

        return render_template("user.html", info=info)

    except:

        # Let the user know about incorrect user ID
        return apology("invalid user id", 400)