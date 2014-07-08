"use strict;"
/*
    Example script for the passport-uwshib module

    This should be run on a server that will be or
    already has been registered with the UW Shibboleth
    Identity Provider (IdP).
*/


const loginUrl = '/login';
const loginCallbackUrl = '/login/callback';

var http = require('http');                     //http server
var https = require('https');                   //https server
var fs = require('fs');                         //file system
var express = require("express");               //express middleware
var morgan = require('morgan');                 //logger for express
var bodyParser = require('body-parser');        //body parsing middleware
var cookieParser = require('cookie-parser');    //cookie parsing middleware
var session = require('express-session');       //express session management
var passport = require('passport');             //authentication middleware
var uwshib = require('passport-uwshib');        //UW Shibboleth auth strategy

///////////////////////////////////////////////////////////////////////////////
// load files and read environment variables
//

//get server's domain name from environment variable
//this is necessary as the passport-saml library requires
//this when we create the Strategy
var domain = process.env.DOMAIN;
if (!domain || domain.length == 0)
    throw new Error('You must specify the domain name of this server via the DOMAIN environment variable!');

var httpPort = process.env.HTTPPORT || 80;
var httpsPort = process.env.HTTPSPORT || 443;

//load public certificate and private key
//used for HTTPS and for signing SAML requests
//put these in a /security subdirectory with the following names,
//or edit the paths used in the following lines
var publicCert = fs.readFileSync('./security/server-cert.pem', 'utf-8');
var privateKey = fs.readFileSync('./security/server-pvk.pem', 'utf-8');

///////////////////////////////////////////////////////////////////////////////
// setup express application and register middleware
//
var app = express();
app.use(morgan({
    format: process.env.LOGFORMAT || 'dev'
}));
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json({type: 'application/json'}));
app.use(cookieParser());
app.use(session({
    secret: fs.readFileSync('./security/session-secret.txt', 'utf-8'),
    cookie: {secret: true}
}));
app.use(passport.initialize());
app.use(passport.session());

//create the UW Shibboleth Strategy and tell Passport to use it
var strategy = new uwshib.Strategy({
    entityId: domain,
    privateKey: privateKey,
    callbackUrl: loginCallbackUrl,
    domain: domain
});

passport.use(strategy);

//These functions are called to serialize the user
//to session state and reconsitute the user on the 
//next request. Normally, you'd save only the netID
//and read the full user profile from your database
//during deserializeUser, but for this example, we
//will save the entire user just to keep it simple
passport.serializeUser(function(user, done){
    done(null, user);
});

passport.deserializeUser(function(user, done){
    done(null, user);
});

///////////////////////////////////////////////////////////////////////////////
// login, login callback, and metadata routes
//
app.get(loginUrl, passport.authenticate(strategy.name), uwshib.backToUrl());
app.post(loginCallbackUrl, passport.authenticate(strategy.name), uwshib.backToUrl());
app.get(uwshib.urls.metadata, uwshib.metadataRoute(strategy, publicCert));

//secure all routes following this
//alternatively, you can use ensureAuth as middleware on specific routes
//example:
//  app.get('protected/resource', uwshib.ensureAuth(loginUrl), function(req, res) {
//      //route code
//  });
app.use(uwshib.ensureAuth(loginUrl));


///////////////////////////////////////////////////////////////////////////////
// application routes
//

//root resource
//just say hello!
//eventually this will be a static middleware that returns our UI pages
app.get('/', 
    function(req, res) {
        //req.user will contain the user object sent on by the
        //passport.deserializeUser() function above
        res.send('Hello ' + req.user.displayName + '!');
    }
);

//general error handler
//if any route throws, this will be called
app.use(function(err, req, res, next){
    console.error(err.stack || err.message);
    res.send(500, 'Server Error! ' + err.message);
});

///////////////////////////////////////////////////////////////////////////////
// web server creation and startup
//

//create the HTTPS server and pass the express app as the handler
var httpsServer = https.createServer({
    key: privateKey,
    cert: publicCert
}, app);

httpsServer.listen(httpsPort, function(){
    console.log('Listening for HTTPS requests on port %d', httpsServer.address().port)
});

//create an HTTP server that always redirects the user to 
//the equivallent HTTPS URL instead
var httpServer = http.createServer(function(req, res) {
    var redirUrl = 'https://' + domain;
    if (httpsPort != 443)
        redirUrl += ':' + httpsPort;
    redirUrl += req.url;

    res.writeHead(301, {'Location': redirUrl});
    res.end();
});

httpServer.listen(httpPort, function() {
    console.log('Listening for HTTP requests on port %d, but will auto-redirect to HTTPS', httpServer.address().port);
});

