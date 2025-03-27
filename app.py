import pathlib
from datetime import datetime
from decimal import Decimal
from typing import Optional
from collections import defaultdict


from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from secrets import token_hex
from flask_migrate import Migrate

# Utility modules
from helpers import apology, login_required, lookup, usd
from loggers import setup_custom_logger


# Loggers
custom_logger = setup_custom_logger()


# Configure application
app = Flask(__name__)

# Custom filter

def format_time(value):
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    return value
app.jinja_env.filters["usd"] = usd
app.jinja_env.filters["format_dt"] = format_time

# Configure session to use filesystem (instead of signed cookies)
app.config["SECRET_KEY"] = token_hex(312) #! This is not secure in a prod environment
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
DATABASE_PATH = pathlib.Path(__file__).parent.absolute() / "finance.db"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + str(DATABASE_PATH)
Session(app)

# Configure CS50 Library to use SQLite database
db:SQLAlchemy = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins='*') #! This is not secure, but since it's a dev environment just let it pass


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    username = db.Column(db.String, nullable=False, unique=True)
    hash = db.Column(db.String, nullable=False)
    cash = db.Column(db.Numeric(precision=10, scale=2), nullable=False, default=10000.00)
    
    transactions = db.relationship('Transaction', backref='user', lazy=True)

    sent_messages = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id')
    recieved_messages = db.relationship('Message', backref='recipient', lazy=True, foreign_keys='Message.recipient_id')

    def __repr__(self):
        return f"<User {self.username}>"

    def set_password(self, secret:str):
        self.hash = generate_password_hash(secret)

    def check_password(self, secret:str) -> bool:
        return check_password_hash(self.hash, secret)

    @classmethod
    def get_by_id(cls, id:int) -> Optional['User']:
        """Retrieve a user by id."""
        return cls.query.get(id)

    @classmethod
    def get_by_name(cls, name:str) -> Optional['User']:
        """Retrieves a user by the username"""
        return cls.query.filter_by(username=name).first()

    def get_stocks(self):
        """ Returns a dict of stock:shares """
        stocks = defaultdict(int)

        for transaction in self.transactions:
            stocks[transaction.stock_ticker] += transaction.shares * (1 if transaction.bought else -1)

        if any(shares < 0 for shares in stocks.values()):
            raise ValueError("One or more values of shares are negative!")

        # custom_logger.debug(stocks)
        return {ticker: shares for ticker, shares in stocks.items() if shares > 0}

    def get_more_stocks(self):
        user_shares = self.get_stocks()
        all_stocks = []
        for ticker, shares in user_shares.items():
            result = lookup(ticker)
            all_stocks.append({
                "symbol": ticker,
                "price": result['price'],
                "shares": shares,
                "total": result['price'] * shares
             })
        return all_stocks

class Transaction(db.Model):
    __tablename__ = "transactions"
    transaction_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    stock_ticker = db.Column(db.String, nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    price_at_purchase = db.Column(db.Numeric, nullable=False)
    time_at_purchase = db.Column(db.DateTime, nullable=False, default=datetime.now())
    bought = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return f"<Transaction {self.transaction_id}>"

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.now())
    read = db.Column(db.Boolean, default=False)

    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])

    messages = db.relationship('Message', backref='conversation', lazy=True)

    @classmethod
    def get_convo(cls, user1_id:int, user2_id:int) -> Optional['Conversation']:
            return Conversation.query.filter(
                ((Conversation.user1_id == user1_id) & (Conversation.user2_id == user2_id)) |
                ((Conversation.user1_id == user2_id) & (Conversation.user2_id == user1_id))
                ).first()



@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response






# TODO: Make a better portfolio page
# TODO: Add better history page where no transaction has occurred
@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user = User.get_by_id(session["user_id"])
    return render_template("portfolio.html", user=user, stocks=user.get_more_stocks())

# My custom routes
@app.route("/stock-data", methods=["GET"])
@login_required
def data():
    symbol = request.args.get("symbol")
    if not symbol:
        return '', 204

    result = lookup(symbol)
    if result is None:
        return '', 204

    return jsonify(result)

@app.route("/user-shares", methods=["POST"])
@login_required
def shares():
    ticker = request.get_json().get("symbol")
    stocks = User.get_by_id(session["user_id"]).get_stocks()
    if ticker in stocks:
        return str(stocks[ticker]), 200
    else:
        return '', 204

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Shares must be given!(as a postive integer)")

        def validate_inp() -> tuple[str|None, dict|None]:
            if symbol is None:
                return "Symbol must be given!"

            lookup_result = lookup(symbol)
            if lookup_result is None:
                return "Invalid Symbol!", None

            if shares <= 0:
                return "Shares must be a positive integer!", None

            return None, lookup_result

        msg, lookup_result = validate_inp()
        if msg:
            return apology(msg)

        def buy_share() -> Optional[str]:
            user:User = User.get_by_id(session['user_id'])
            price_of_purchase = Decimal(lookup_result["price"] * shares)
            if price_of_purchase > user.cash:
                return "You are broke!"
            user.cash -= price_of_purchase

            transaction = Transaction(user_id=user.id, stock_ticker=lookup_result['symbol'], shares=shares, price_at_purchase=price_of_purchase,
                                      bought=True)
            db.session.add(transaction)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                custom_logger.critical(str(e))
                return "An error occured. Sorry!"

            return

        if msg := buy_share():
            return apology(msg)

        flash("Purchase successful!")
        return redirect("/")

    return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_history = Transaction.query.filter_by(user_id=session["user_id"]).order_by(Transaction.time_at_purchase.desc()).all()
    return render_template("history.html", history=user_history)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.pop("user_id", None)

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            flash("Must provide username")
            return redirect("/login")

        # Ensure password was submitted
        if not password:
            flash("Must provide password")
            return redirect("/login")

        # Query database for username
        user:User|None = User.query.filter_by(username=username).first()
        # Ensure username exists and password is correct
        if not user:
            flash("Invalid Username or Password")
            return redirect("/login")

        # Check password
        if not user.check_password(password):
            flash("Invalid Username or Password")
            return redirect("/login")

        # Remember which user has logged in
        session["user_id"] = user.id
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)

    return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

# TODO: MAKE MORE BEAUTIFUL
@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        ticker = request.form.get("symbol")
        if ticker is None:
            return apology("Enter a Symbol!")

        result = lookup(ticker)
        if result is None:
            return apology("Invalid Symbol!")

        return render_template("quote.html", quote=result)


    return render_template("quote.html")

def is_valid(username:str, password:str, double:str) -> bool:
    """Checks if: (i) username isn't already in the database,
        (ii) Username meets the requirements
        (iii) Password meets the requirements"""
    if not username:
        raise ValueError("You must enter a username!")

    if not password:
        raise ValueError("You must enter a password!")

    if not double:
        raise ValueError("You must enter the password again!")

    # if len(password) <= 8:
    #     raise ValueError("Password must be longer than 8 characters")

    if double != password:
        raise ValueError("Passwords do not match!")


def create_new_user(username:str, password:str) -> User:
    """ Adds a new user to the users table"""
    try:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise ValueError

    return new_user


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        double = request.form.get("confirmation")

        try:
            is_valid(username, password, double)
        except ValueError as e:
            message = str(e)
            return apology(message)

        try:
            create_new_user(username, password)
        except ValueError:
            return apology("Username already taken!")

        flash("You have been successfully registered!")

        return redirect("/login")

    return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        ticker = request.form.get("symbol")
        try:
            stock_shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Invalid Shares!")

        current_stocks = User.get_by_id(session["user_id"]).get_stocks()

        def validate_inp() -> tuple[str|None, dict|None]:
            if ticker is None:
                return "Symbol must be given!"

            lookup_result = lookup(ticker)
            if lookup_result is None:
                return "Invalid Symbol!", None

            if stock_shares <= 0:
                return "Shares must be a positive integer!", None

            if not ticker in current_stocks:
                return "You do not own that stock!", None

            if stock_shares > current_stocks[ticker]:
                return "You do not own that many shares!", None

            if stock_shares == 0:
                return "Why are you selling 0 shares?!", None

            return None, lookup_result


        msg, lookup_result = validate_inp()

        if msg:
            return apology(msg)

        def sell_shares() -> Optional[str]:
            user = User.get_by_id(session['user_id'])

            total_sold_value = Decimal(lookup_result["price"] * stock_shares)


            user.cash += total_sold_value

            transaction = Transaction(user_id=user.id, stock_ticker=lookup_result["symbol"],
                                      shares=stock_shares, price_at_purchase=total_sold_value,
                                      bought=False)

            db.session.add(transaction)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                custom_logger.critical(str(e))
                return "An error occured. Sorry!"

            return

        if msg := sell_shares():
            return apology(msg)

        flash("Stock sold successfully!")
        return redirect("/")


    try:
        user_stocks = User.get_by_id(session["user_id"]).get_stocks()
    except ValueError as e:
        custom_logger.critical(str(e))
        return apology("Something has gone wrong...")

    # custom_logger.debug(user_stocks)

    return render_template("sell.html", stocks=user_stocks)


@app.route("/conversation", methods=["GET", "POST"])
@login_required
def conversations():
    """Returns every conversation the user has.
    If requested via POST, create a new conversation"""
    if request.method == "POST":
        recipient_name = request.form.get("username")
        if recipient_name is None:
            flash("Enter a username!")
            return redirect("/conversation")
        
        recipient = User.get_by_name(recipient_name)

        if recipient is None:
            flash("User does not exist!")
            return redirect("/conversation")
        

        if recipient.id == session["user_id"]:
            flash("You can't converse with yourself!")
            return redirect("/conversation")

        def create_new_convo():
            # TODO: Create a new conversation
            prexisting_convo = Conversation.get_convo(session["user_id"], recipient.id)           
            
            if prexisting_convo:
                return prexisting_convo
            
            try:
                new_convo = Conversation(user1_id=session["user_id"], user2_id=recipient.id)
                db.session.add(new_convo)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                custom_logger.critical(str(e))
                return None
            
            return new_convo


        convo = create_new_convo()
        if convo is None:
            flash("An error occured! sorry!")
            return redirect("/conversation")

        return redirect(f"/conversation/{recipient.id}")

    all_convos = Conversation.query.filter(
        (Conversation.user1_id == session["user_id"]) |
        (Conversation.user2_id == session["user_id"])
    ).all()

    return render_template("convos.html", conversations=all_convos)

# * SOCKETIO OPERATIONS

@socketio.on("join_convo")
@login_required
def on_join(data):
    conversation_id = data['conversation_id']
    room = f"conversation_{conversation_id}"
    custom_logger.debug(f"{User.get_by_id( session["user_id"])} joined a conversation {Conversation.query.get(conversation_id)} ")
    join_room(room)

@socketio.on("disconnect")
@login_required
def handle_disconnet():
    pass

@socketio.on("leave_convo")
@login_required
def on_leave(data):
    conversation_id = data['conversation_id']
    room = f"conversation_{conversation_id}"
    leave_room(room)

@socketio.on("send_message")
@login_required
def handle_message(data):
    recipient_id = data.get('recipient_id')
    content = data.get('content')

    if not recipient_id or not content:
        return {'error': 'Invalid message data'}
    
    convo = Conversation.get_convo(session["user_id"], recipient_id)
    if not convo:
        return {'error': 'Conversation does not exist'}
    
    message = Message(
        content=content,
        sender_id=session["user_id"],
        recipient_id=recipient_id,
        conversation_id=convo.id
    )

    try:
        db.session.add(message)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        custom_logger.critical(str(e))
        return {'error': 'Internal Server mishaps'}
    
    message_data = {
        'id': message.id,
        'content': message.content,
        'sender_id': session["user_id"],
        'sender_username': User.get_by_id(session["user_id"]).username,
        'timestamp': message.timestamp.isoformat()
    }

    room = f"conversation_{convo.id}"
    custom_logger.debug(f"{User.get_by_id(session["user_id"])} said {message.content}")
    emit("receive_message", message_data, room=room)

    return {'status': 'sucess'}

# TODO: MAke this work
@app.route("/conversation/<int:user_id>")
@login_required
def conversation(user_id):
    """Returns the messages in a conversation"""
    other_user = User.get_by_id(user_id)
    if other_user is None:
        flash("conversation doesn't exist!")
        return redirect("/conversation")

    convo = Conversation.get_convo(session["user_id"], other_user.id)
    messages = convo.messages

    return render_template("convo.html", recipient=other_user, messages=messages, conversation=convo)


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    socketio.run(app, debug=True)
