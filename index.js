const express = require('express');
const jose = require('node-jose');
const jws = require('jws');
const fs = require('fs');
const ms = require('ms');
const morgan = require('morgan');

const app = express();

app.use(morgan("common"));

const Claim = {
    sub: "1103132074"
}

app.get('/users', (req, res) => {
    return res.json({ ...req.headers })
});

app.post('/token', async (req, res) => {
    return res.json({ 
        "access_token": { 
            "aud": "https://your.krakend.io", 
            "iss": "https://your-backend", 
            "sub": "1234567890qwertyuio", 
            "jti": "mnb23vcsrt756yuiomnbvcx98ertyuiop", 
            "roles": ["role_a", "role_b"], 
            "exp": 1735689600 
        }, 
        "refresh_token": { 
            "aud": "https://your.krakend.io", 
            "iss": "https://your-backend", 
            "sub": "1234567890qwertyuio", 
            "jti": "mnb23vcsrt756yuiomn12876bvcx98ertyuiop", 
            "exp": 1735689600 
        }, 
        "exp": 1735689600 
     });
});

app.get('/jwt-token', async (req, res) => {
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

app.get('/jwks', async (req, res) => {

    const ks = require('./keys.json');
    return res.json(ks);
});

app.get('/generate', async (req, res) => {
    const keyStore = jose.JWK.createKeyStore();
    await keyStore.generate('RSA', 2048, {alg: 'RS256', use: 'sig' });
    fs.writeFileSync('keys.json', JSON.stringify(keyStore.toJSON(true), null, '  '));
    
    return res.json({ message: 'ok' });
});

app.get('/verify', async (req, res) => {
    const [_, tokenString] = req.headers['authorization'].split(" ");

    const keys = fs.readFileSync('keys.json');
    const keyStore = await jose.JWK.asKeyStore(keys.toString());

    const tokenObj = jws.decode(tokenString);

    const kid = tokenObj.header.kid;
    const key = keyStore.get(kid);

    await jose.JWS.createVerify(key).verify(tokenString);

    return res.json({ message: "authenticated" });
})

app.listen(8000, '0.0.0.0', () => {
    console.log('app started on port 0.0.0.0:8000')
});
