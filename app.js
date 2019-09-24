const express = require('express');
var app = express();
const bodyParser = require('body-parser');
var speakeasy = require('speakeasy');
var QRCode = require('qrcode');
const path = require('path');

app.use(bodyParser.json());

// single in-memory user
let user = {
    'firstName': "Shannon",
    'lastName': "Miko",
    email: "shan.miko@test.com",
    password: "test"
}

// login API supports both normal auth and 2fa
app.post('/login', function(req, res){
    if(!user.twofactor || !user.twofactor.secret){ // if 2fa is not enabled by the user
    	
        //check user credentials
        if(req.body.email == user.email && req.body.password == user.password){
            return res.send('success');
        }
        return res.status(400).send('Invald email or password');
        
    } else { // if 2fa is enabled
        if(req.body.email != user.email || req.body.password != user.password)
            return res.status(400).send('Invalid email or password');

        // check if temp token is passed - if not then ask for it
        if(!req.headers['x-otp'])
            return res.status(206).send('Please enter token number to continue');

        // validate temp token
        var verified = speakeasy.totp.verify({
            secret: user.twofactor.secret,
            encoding: 'base32',
            token: req.headers['x-otp']
        });
        
        if(verified)
            return res.send('success');
        else
            return res.status(400).send('Invalid Token');
    }
});

// set up 2fa for logged in user
app.post('/twofactor/setup', function(req, res){
    const secret = speakeasy.generateSecret({length: 10});
    QRCode.toDataURL(secret.otpauth_url, (err, data_url)=>{
        //save details to logged in user
        user.twofactor = {
            secret: "",
            tempSecret: secret.base32,
            dataURL: data_url,
            otpURL: secret.otpauth_url
        };
        return res.json({
            message: 'Proceed to Setup',
            tempSecret: secret.base32,
            dataURL: data_url,
            otpURL: secret.otpauth_url
        });
    });
});

// get 2fa details
app.get('/twofactor/setup', function(req, res){
    res.json(user.twofactor);
});

// disable 2fa
app.delete('/twofactor/setup', function(req, res){
    delete user.twofactor;
    res.send('success');
});

// before enabling totp based 2fa; it's important to verify, so that we don't end up locking the user.
app.post('/twofactor/verify', function(req, res) {
    var verified = speakeasy.totp.verify({
        secret: user.twofactor.tempSecret, // secret of the logged in user
        encoding: 'base32',
        token: req.body.token
    });
    if(verified) {
        user.twofactor.secret = user.twofactor.tempSecret;
        return res.send('Two-factor authentication has been enabled');
    }
    return res.status(400).send('Invalid token, verification failed');
});

// front-end app
app.get('/', function(req, res) {
    res.sendFile(path.join(__dirname+'/vue.app.html'));
});

app.listen('3000', ()=>{
    console.log('App running on 3000');
});
