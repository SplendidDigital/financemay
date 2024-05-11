import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response












@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Retrieve user's portfolio from the database
    portfolio = db.execute(
        "SELECT symbol, shares FROM portfolio WHERE user_id = ?",
        (session["user_id"],)
    )



    # Initialize variables to store total portfolio value and a list to hold individual stock details
    total_value = 0
    stocks = []

    # Loop through each stock in the portfolio
    for stock in portfolio:
        # Lookup current stock price
        quote = lookup(stock["symbol"])
        if quote is not None:

            # Calculate the total value of each stock
            total_stock_value_current_price = quote["price"] * stock["shares"]
            total_value += total_stock_value_current_price

            # Append stock details to the list
            stocks.append({
                "symbol": stock["symbol"],
                "shares": stock["shares"],
                "price": quote["price"],
                "total": total_stock_value_current_price  # Change total to total_stock_value
            })


    # Update the 'total' key in each stock dictionary to hold cumulative total portfolio value
    #for stock in stocks:
        #stock["total"] = total_value

     # Retrieve user's cash balance from the database
     # Retrieve user's cash balance
    cash_query = db.execute("SELECT cash FROM users WHERE id = ?", (session["user_id"],))
    cash_row = cash_query[0] if cash_query else None  # Fetch the first row
    cash = cash_row["cash"] if cash_row else None  # Extract cash value from the row

    # Calculate total portfolio value including cash balance
    final_value = total_value + cash

    return render_template("index.html", stocks = stocks, final_value = final_value, cash=cash, total_value=total_value)




@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Ensure symbol and shares were submitted
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        if not symbol:
            return apology("must provide symbol", 400)
        elif not shares:
            return apology("must provide number of shares", 400)
        try:
            shares = int(shares)
            if shares <= 0:
                return apology("number of shares must be positive", 400)
        except ValueError:
            return apology("number of shares must be a valid integer", 400)

        # Lookup the current price of the stock
        quote = lookup(symbol)
        if quote is None:
            return apology("invalid symbol", 400)

        # Retrieve user's cash balance
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        # Calculate total cost of the shares
        total_cost = quote["price"] * shares

        # Ensure user has enough cash to buy the shares
        if total_cost > cash:
            return apology("not enough cash", 403)

        # Update user's cash balance
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, session["user_id"])

        # Add the purchased shares to the user's portfolio
        db.execute("INSERT INTO portfolio (user_id, symbol, shares) VALUES (?, ?, ?) ON CONFLICT(user_id, symbol) DO UPDATE SET shares = shares + ?", session["user_id"], symbol, shares, shares)

        # Record the transaction in the history table
        db.execute("INSERT INTO history (user_id, symbol, shares, price, type) VALUES (?, ?, ?, ?, 'buy')", session["user_id"], symbol, shares, quote["price"])

        flash("Shares bought successfully!")
        return redirect("/")

    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Retrieve user's transaction history from the database
    history = db.execute("SELECT * FROM history WHERE user_id = ?", session["user_id"])

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        if not symbol:
            return apology("must provide symbol", 400)
        quote = lookup(symbol)
        if quote is None:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", quote=quote)

    else:
        return render_template("quote.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("must provide username", 400)  # Return 400 for empty username
        elif not password:
            return apology("must provide password", 400)  # Return 400 for empty password
        elif password != confirmation:
            return apology("passwords do not match", 400)  # Return 400 for mismatched passwords

        # Check if the username already exists
        existing_user = db.execute("SELECT * FROM users WHERE username = ?", username)
        if existing_user:
            return apology("username already exists", 400)  # Return 400 for existing username

        hash_password = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash_password)
        except:
            return apology("unable to register user", 500)  # Return 500 for server error

        flash("Registered successfully!")
        return redirect("/login")

    else:
        return render_template("register.html")



@app.route("/quoted", methods=["GET", "POST"])
@login_required
def quoted():
    """Display stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        if not symbol:
            return apology("must provide symbol", 400)

        # Lookup the current price of the stock
        quote = lookup(symbol)
        if quote is None:
            return apology("invalid symbol", 403)

        return render_template("quoted.html", quote=quote)

    else:
        # If accessed directly, render an apology
        return apology("invalid request", 403)




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))
        if not symbol:
            return apology("must provide symbol", 400)
        elif not shares:
            return apology("must provide number of shares", 400)

        # Retrieve user's portfolio to check if they have enough shares to sell
        portfolio = db.execute(
            "SELECT symbol, shares FROM portfolio WHERE user_id = ?", session["user_id"]
        )
        for stock in portfolio:
            if stock["symbol"] == symbol:
                if stock["shares"] < shares:
                    return apology("not enough shares", 400)

                # Lookup the current price of the stock
                quote = lookup(symbol)
                if quote is None:
                    return apology("invalid symbol", 403)

                # Update user's cash balance
                total_sale = quote["price"] * shares
                db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_sale, session["user_id"])
                print(total_sale)
                # Update user's portfolio
                db.execute("UPDATE portfolio SET shares = shares - ? WHERE user_id = ? AND symbol = ?", shares, session["user_id"], symbol)


                # Record the transaction in the history table
                db.execute("INSERT INTO history (user_id, symbol, shares, price, type) VALUES (?, ?, ?, ?, 'sell')", session["user_id"], symbol, shares, quote["price"])

                flash("Shares sold successfully!")
                return redirect("/")

        return apology("symbol not found in portfolio", 403)

    else:
        # Retrieve user's portfolio to get symbols of stocks they own
        portfolio = db.execute(
            "SELECT symbol FROM portfolio WHERE user_id = ?", session["user_id"]
        )

        symbols = [stock["symbol"] for stock in portfolio]

        return render_template("sell.html", symbols=symbols)

from werkzeug.security import check_password_hash, generate_password_hash

from werkzeug.security import check_password_hash, generate_password_hash

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        # Get old and new passwords from form
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")

        # Retrieve user's hashed password from the database
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Check if user exists
        if not user:
            return apology("User not found", 403)

        hashed_password = user[0]["hash"]

        # Verify old password
        if not check_password_hash(hashed_password, old_password):
            return apology("Incorrect old password", 403)

        # Hash the new password
        hashed_new_password = generate_password_hash(new_password)

        # Update user's password in the database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed_new_password, session["user_id"])

        flash("Password changed successfully!")
        return redirect("/")
    else:
        return render_template("change_password.html")






if __name__ == '__main__':
    app.run(host='0.0.0.0')

