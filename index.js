const express = require('express');
const jose = require('node-jose');
const fs = require('fs');
const ms = require('ms');

const app = express();
const Claim = {
    sub: "1103132074"
}

app.get('/users', (req, res) => {
    return res.json({ ...req.headers })
});

app.get('/token', async (req, res) => {
    const ks = fs.readFileSync('keys.json')
    const keyStore = await jose.JWK.asKeyStore(ks.toString())
    const [key] = keyStore.all({ use: 'sig' })

    const opt = { compact: true, jwk: key, fields: { typ: 'JWT' } }
    const payload = JSON.stringify({
      exp: Math.floor((Date.now() + ms('1d')) / 1000),
      iat: Math.floor(Date.now() / 1000),
      ...Claim
    })

    const token = await jose.JWS.createSign(opt, key)
      .update(payload)
      .final()

    return res.json({ token });
});

app.get('/oauth2/jwks', async (req, res) => {
    console.log('jwks');
    const ks = fs.readFileSync('keys.json');
    const keyStore = await jose.JWK.asKeyStore(ks.toString());
    return res.json(keyStore.toJSON());
});

app.get('/oauth2/symetric', async (req, res) => {
    console.log('jwks');
    const ks = require('./symetric.json');
    // const keyStore = await jose.JWK.asKeyStore(ks.toString());
    return res.json(ks);
});

app.get('/add', async (req, res) => {
    const keyStore = jose.JWK.createKeyStore();
    await keyStore.generate('RSA', 2048, {alg: 'RS256', use: 'sig' });
    fs.writeFileSync('keys.json', JSON.stringify(keyStore.toJSON(true), null, '  '));
    
    return res.json({ message: 'ok' });
});

app.listen(8000, '0.0.0.0', () => {
    console.log('app started on port 0.0.0.0:8000')
});
