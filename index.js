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

// return all headers to show propagated claims
app.get('/users', (req, res) => {
    return res.json({ ...req.headers })
});

// generate token to be signed as JWT
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

// generate JWT token the traditional way
app.get('/jwt-token', async (req, res) => {
    const ks = fs.readFileSync('keys.json')
    const keyStore = await jose.JWK.asKeyStore(ks.toString())
    const keys = keyStore.all({ use: 'sig' })

    const key = keys[1]; // choose which key to use

    const opt = { compact: true, fields: { typ: 'JWT' } }
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

// for signing, keys need to be plain
app.get('/symetric', async (req, res) => {
    const ks = require('./keys.json');
    return res.json(ks);
});

// for verifying, keys need to be load as key store
app.get('/jwks', async (req, res) => {
    const ks = require('./keys.json');
    const keyStore = await jose.JWK.asKeyStore(ks);
    return res.json(keyStore.toJSON());
});

// regenerate JWK into JSON file
app.get('/generate', async (req, res) => {
    const keyStore = jose.JWK.createKeyStore();
    await keyStore.generate('RSA', 2048, {alg: 'RS256', use: 'sig' });
    fs.writeFileSync('keys.json', JSON.stringify(keyStore.toJSON(true), null, '  '));
    
    return res.json({ message: 'ok' });
});

// verify JWT signature with JWK
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

// regenerate JWK into JSON file
app.get('/generate-from-secret', async (req, res) => {
    const keyStore = jose.JWK.createKeyStore();
    await keyStore.generate('oct', 256, { alg: 'HS256', k: "wow" });
    return res.json(keyStore.toJSON());
});

app.listen(8000, '0.0.0.0', () => {
    console.log('app started on port 0.0.0.0:8000')
});
