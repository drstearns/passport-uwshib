Passport-UWShib
===============

Passport authentication strategy that works with the University of Washington's Shibboleth single-sign on service. This uses the fabulous [passport-saml](https://github.com/bergie/passport-saml) module for all the heavy lifting, but sets all the default options so that it works properly with the UW Shibboleth Identity Provider (IdP).

Note that in order to use the UW IdP for authentication, **you must [register your server](https://iam-tools.u.washington.edu/spreg/)**. During the registration process, it will attempt to gather your server's metadata via the route /Shibboleth.sso/Metadata. This module provides an implementation for that route, but you have to set that up in your main server script (see [/example/server.js](https://github.com/drstearns/passport-uwshib/blob/master/example/server.js)).

While registering, you must also specify which user profile attributes you want. See the [Guide to Attributes Available from the UW IdP](https://wiki.cac.washington.edu/display/infra/Guide+to+Attributes+Available+from+the+UW+IdP) for more information.

Installation
------------
    npm install passport-uwshib

or if using a [package.json file](https://www.npmjs.org/doc/package.json.html), add this line to your dependencies hash:

    "passport-uwshib": "*"

and do an `npm install` or `npm update` to get the most current version.

Usage
-----
There is a fully-working example server script in [/example/server.js](https://github.com/drstearns/passport-uwshib/blob/master/example/server.js), and an associated [package.json](ttps://github.com/drstearns/passport-uwshib/blob/master/example/package.json), which you can use to install all the necessary packages to make the example script run (express, express middleware, passport, etc.). Refer to that as I explain what it is doing.

This module provides a Strategy for the [Passport](http://passportjs.org/) framework, which is typically used with [Express](http://expressjs.com/). Thus, there are several modules you need to require in your server script in addition to this module.

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

The example script then gets the server's domain name from an environment variable. This allows you to run the example script without modification. Simply export a value for `DOMAIN` and run the script.

    export DOMAIN=mydomain.uw.edu
    node server.js

You can also override the default HTTP and HTTPS ports if you wish by specifying `HTTPPORT` and `HTTPSPORT` environment variables.

The example script then loads a public certificate and associated private key from two files in a `/security` subdirectory.

    var publicCert = fs.readFileSync('./security/server-cert.pem', 'utf-8');
    var privateKey = fs.readFileSync('./security/server-pvk.pem', 'utf-8');

These are used not only for the HTTPS server, but also to sign requests sent to the UW IdP. You can use [openssl](http://www.sslshopper.com/article-most-common-openssl-commands.html) to generate keys and certificate signing requests. The UW IdP seems to require that your server responds to HTTPS requests, so you should get a signed certificate for your server before trying to register it.

The script continues by creating a typical Express application and registering the typical middleware. For more information on this, see the [Passport.js site](http://passportjs.org/).

Then the script creates the UW Shibboleth Strategy, and tells Passport to use it.

    //create the UW Shibboleth Strategy and tell Passport to use it
    var strategy = new uwshib.Strategy({
        entityId: domain,
        privateKey: privateKey,
        callbackUrl: loginCallbackUrl,
        domain: domain
    });

    passport.use(strategy);

The name of the strategy is `'uwsaml'`, but you can use the `.name` property of the Strategy to refer to that.

You will typically want to use sessions to allow users to authenticate only once per-sesion. The next functions are called by Passport to serialize and deserialize the user to the session. As noted in the comments, you would typically want to serialize only the unique ID (`.netID`) and reconstitute the user from your database during deserialzie. But to keep things simple, the script serializes the entire user and deserializes it again.

    passport.serializeUser(function(user, done){
        done(null, user);
    });

    passport.deserializeUser(function(user, done){
        done(null, user);
    });

Next, the script registers a few routes to handle login, the login callback, and the standard metadata. This module provides implementations for the metadata route, and you use passport.authenticate for the login and login callback routes. The login route will redirect the user to the UW single sign-on page, and the UW IdP will then redirect the user back to the login callback route.

    app.get(loginUrl, passport.authenticate(strategy.name), uwshib.backToUrl());
    app.post(loginCallbackUrl, passport.authenticate(strategy.name), uwshib.backToUrl());
    app.get(uwshib.urls.metadata, uwshib.metadataRoute(strategy, publicCert));

The `uwshib.backToUrl()` is a convenience middleware that will redirect the browser back to the URL that was originally requested before authentication.

Lastly, the script tells Express to use the `ensureAuth()` middleware provided by this module to secure all routes declared after this.

    //secure all routes following this
    app.use(uwshib.ensureAuth(loginUrl));

Any route requested after this middleware will require authentication. When requested, those routes will automatically redirect to the `loginUrl` if the user has not already authenticated. After successful authentication, the browser will be redirected back to the original URL, and the user information will be available via the `.user` property on the request object.

Note that `ensureAuth` can also be used to selectively secure routes. For example:

    app.get('protected/resource', ensureAuth(loginUrl), function(req, res) {
        //user has authenticated, do normal route processing
        //user is available via req.user
    });
