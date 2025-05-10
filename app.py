from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import requests
import time
import sqlite3
from flask import g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_key_here")

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('users.db')
        g.db.row_factory = sqlite3.Row
    return g.db

def get_btc_usd_price():
    try:
        url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
        response = requests.get(url)
        data = response.json()
        return data["bitcoin"]["usd"]
    except Exception as e:
        print("Price fetch failed:", e)
        return 0

DATABASE = 'users.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

SHARED_BTC_ADDRESS = 'bc1qg9aph4er0d9rds0f94smgm89ey8n2qamxnsmkp'

@app.route('/register', methods=['GET', 'POST'])
def register():
    db = get_db()
    referred_by = request.args.get('ref')  # get referral if present

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        hashed_password = generate_password_hash(password)

        try:
            db.execute(
                'INSERT INTO users (username, email, password_hash, referred_by) VALUES (?, ?, ?, ?)',
                (username, email, hashed_password, referred_by)
            )
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return 'Username or email already exists.'

    return render_template('register.html', referred_by=referred_by)

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Fetch balance from the database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    balance = result[0] if result else 0.0

    return render_template('home.html', username=session['username'], balance=balance)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/account")
def account():
    if "username" not in session:
        return redirect("/login")
    
    username = session["username"]

    db = get_db()
    c = db.cursor()
    c.execute("SELECT balance FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    balance = result[0] if result else 0.0

    # Example static price. Replace with real-time price logic if needed
    btc_price = 65000
    balance_usd = round(balance * btc_price, 2)

    deposit_address = "bc1qg9aph4er0d9rds0f94smgm89ey8n2qamxnsmkp"

    return render_template("account.html",
        balance=balance,
        balance_usd=balance_usd,
        deposit_address=deposit_address,
        username=username
    )

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    message = None

    if request.method == 'POST':
        txid = request.form['txid'].strip()
        address = "bc1qg9aph4er0d9rds0f94smgm89ey8n2qamxnsmkp"

        # Check if transaction already exists
        existing = db.execute('SELECT * FROM transactions WHERE txid = ?', (txid,)).fetchone()
        if existing:
            message = "This transaction has already been processed."
        else:
            try:
                res = requests.get(f"https://blockstream.info/api/tx/{txid}")
                if res.status_code != 200:
                    message = "Transaction not found."
                else:
                    tx_data = res.json()
                    status = tx_data.get('status', {})
                    if not status.get('confirmed', False):
                        message = "Transaction is not yet confirmed."
                    else:
                        outputs = tx_data['vout']
                        amount_btc = sum(
                            out['value'] for out in outputs
                            if address == out.get('scriptpubkey_address')
                        ) / 1e8  # convert sats to BTC

                        if amount_btc == 0:
                            message = "Transaction does not send to our deposit address."
                        else:
                            # Credit user's balance
                            db.execute(
                                'UPDATE users SET balance = balance + ? WHERE id = ?',
                                (amount_btc, session['user_id'])
                            )
                            db.execute(
                                'INSERT INTO transactions (user_id, txid, amount, status, type) VALUES (?, ?, ?, ?, ?)',
                                (session['user_id'], txid, amount_btc, 'confirmed', 'deposit')
                            )

                            # Referral bonus logic
                            if amount_btc >= 0.001:
                                user = db.execute('SELECT referrer_id FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                                if user and user['referrer_id']:
                                    ref_bonus = round(amount_btc * 0.07, 8)
                                    db.execute(
                                        'UPDATE users SET balance = balance + ? WHERE id = ?',
                                        (ref_bonus, user['referrer_id'])
                                    )
                                    db.execute(
                                        'INSERT INTO referral_rewards (referrer_id, referred_id, amount) VALUES (?, ?, ?)',
                                        (user['referrer_id'], session['user_id'], ref_bonus)
                                    )

                            db.commit()
                            message = f"Deposit of {amount_btc:.8f} BTC successful!"
            except Exception as e:
                print("Deposit error:", e)
                message = "Error verifying transaction."

    # Fetch user's deposit history
    deposits = db.execute(
        'SELECT amount, txid, status, timestamp FROM transactions WHERE user_id = ? AND type = ?',
        (session['user_id'], 'deposit')
    ).fetchall()

    return render_template('deposit.html', message=message, deposits=deposits)

@app.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()
    error = None

    if request.method == 'POST':
        identifier = request.form['identifier']  # username or email
        password = request.form['password']

        user = db.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            (identifier, identifier)
        ).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']  # To use {{ username }} in templates
            return redirect(url_for('home'))
        else:
            error = 'Invalid username/email or password.'

    return render_template('login.html', error=error)

@app.route('/earn')
def earn():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()

    # Get the logged-in user's username
    user = db.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    username = user['username'] if user else ''

    # Get total earnings
    earnings = db.execute(
        'SELECT SUM(amount) as total FROM referral_rewards WHERE referrer_id = ?', (session['user_id'],)
    ).fetchone()
    total_earned = round(earnings['total'] or 0.0, 8)

    # Get reward history
    history = db.execute(
        '''SELECT u.username as referred_username, r.amount, r.timestamp
           FROM referral_rewards r
           JOIN users u ON r.referred_id = u.id
           WHERE r.referrer_id = ?
           ORDER BY r.timestamp DESC''',
        (session['user_id'],)
    ).fetchall()

    return render_template('earn.html', username=username, total_earned=total_earned, history=history)

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT balance, btc_address FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()

    if not user:
        return "User not found."

    if request.method == 'POST':
        try:
            amount = float(request.form['withdraw_amount'])
        except ValueError:
            return "Invalid amount."

        fee = amount * 0.02
        total = amount + fee

        if total > user[0]:
            flash("Insufficient balance.")
            return redirect('/withdraw')

        if not user[1]:
            flash("No bound address found. Please bind your BTC address.")
            return redirect('/withdraw')

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (total, user_id))
        c.execute('INSERT INTO transactions (user_id, type, amount, address, status) VALUES (?, ?, ?, ?, ?)', 
                  (user_id, 'withdraw', amount, user[1], 'pending'))
        conn.commit()
        conn.close()
        flash("Withdrawal request submitted successfully.")
        return redirect('/withdraw-record')

    return render_template('withdraw.html', btc_address=user[1])

@app.route('/withdrawals')
def withdrawals():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT amount, fee, address, status, timestamp, txid FROM withdrawals WHERE user_id = ? ORDER BY timestamp DESC", (session['user_id'],))
    records = c.fetchall()
    conn.close()

    return render_template('withdrawals.html', withdrawals=records)

@app.route('/withdraw-record')
def withdraw_record():
    # Fetch user's past withdrawals from the database (replace this with actual DB logic)
    user_id = session.get('user_id')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT address, amount, status, timestamp FROM withdrawals WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
    records = c.fetchall()
    conn.close()
    return render_template('withdraw_record.html', records=records)

@app.route('/convert')
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('convert.html')

@app.route('/transfer')
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('transfer.html')

@app.route('/bind-address', methods=['POST'])
def bind_address():
    if 'user_id' not in session:
        return redirect('/login')

    btc_address = request.form['btc_address']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET btc_address = ? WHERE id = ?", (btc_address, session['user_id']))
    conn.commit()
    conn.close()
    flash('BTC address bound successfully.')
    return redirect('/withdraw')

import requests

@app.route('/assets')
def assets():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT balance, exchange, trade, perpetual FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()

    if user:
        total_btc = user[0]
        exchange = user[1]
        trade = user[2]
        perpetual = user[3]

        # Fetch live BTC price in USD from Coingecko
        try:
            r = requests.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd')
            btc_usd = r.json()['bitcoin']['usd']
        except:
            btc_usd = 0  # fallback

        total_usd = round(total_btc * btc_usd, 2)

        return render_template('assets.html',
                               total=total_btc,
                               total_usd=total_usd,
                               exchange=exchange,
                               trade=trade,
                               perpetual=perpetual)
    return redirect(url_for('login'))

@app.route("/history")
def history():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC", (user_id,))
    transactions = cursor.fetchall()
    conn.close()

    return render_template("history.html", transactions=transactions)

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == "admin" and password == "admin123":
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid admin credentials")
    return render_template('admin_login.html')

@app.route('/admin-dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    txs = db.execute('SELECT * FROM transactions ORDER BY timestamp DESC').fetchall()
    return render_template('admin_dashboard.html', users=users, txs=txs)

if __name__ == '__main__':
    app.run(debug=True)

