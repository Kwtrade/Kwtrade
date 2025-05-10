const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const axios = require('axios');
const bcrypt = require('bcryptjs');

const app = express();
const port = 3000;
const USERS_FILE = './users.json';

// Serve static files from the "public" folder (your HTML)
app.use(express.static('public'));
app.use(bodyParser.json());

// Load or initialize users
let users = fs.existsSync(USERS_FILE) ? JSON.parse(fs.readFileSync(USERS_FILE)) : {};

function saveUsers() {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Register
app.post('/register', (req, res) => {
    const { username, password, btcAddress } = req.body;
    if (users[username]) return res.status(400).send('User exists');

    const hashed = bcrypt.hashSync(password, 8);
    users[username] = { password: hashed, btcAddress, balance: 0 };
    saveUsers();
    res.send('Registered');
});

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users[username];
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).send('Invalid credentials');
    }
    res.send(`Logged in. BTC Address: ${user.btcAddress}`);
});

// Check BTC balance
app.get('/balance/:username', async (req, res) => {
    const user = users[req.params.username];
    if (!user) return res.status(404).send('User not found');

    try {
        const url = `https://blockstream.info/api/address/${user.btcAddress}`;
        const { data } = await axios.get(url);
        user.balance = data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum;
        saveUsers();
        res.send({ balance_sats: user.balance });
    } catch (err) {
        res.status(500).send('API error');
    }
});

app.listen(port, () => console.log(`Running on http://localhost:${port}`));
