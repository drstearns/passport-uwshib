
"use strict;"

/*
    UW Shibboleth Passport Authentication Module

    This module exposes a passport Strategy object that is pre-configured to
    work with the UW's Shibboleth identity provider (IdP). To use this, you 
    must register your server with the UW IdP, and you can use the 
    metadataRoute() method below to provide the metadata necessary for 
    registration via the standard metadata url (urls.metadata).

    author: Dave Stearns
*/

const passport = require('passport');
const saml = require('passport-saml');
const util = require('util');

const uwIdPCert = 'MIID/TCCAuWgAwIBAgIJAMoYJbDt9lKKMA0GCSqGSIb3DQEBBQUAMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEhMB8GA1UEChMYVW5pdmVyc2l0eSBvZiBXYXNoaW5ndG9uMR0wGwYDVQQDExRpZHAudS53YXNoaW5ndG9uLmVkdTAeFw0xMTA0MjYxOTEwMzlaFw0yMTA0MjMxOTEwMzlaMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEhMB8GA1UEChMYVW5pdmVyc2l0eSBvZiBXYXNoaW5ndG9uMR0wGwYDVQQDExRpZHAudS53YXNoaW5ndG9uLmVkdTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMH9G8m68L0Hf9bmf4/7c+ERxgDQrbq50NfSi2YTQWc1veUIPYbZy1agSNuc4dwn3RtC0uOQbdNTYUAiVTcYgaYceJVB7syWf9QyGIrglZPMu98c5hWb7vqwvs6d3s2Sm7tBib2v6xQDDiZ4KJxpdAvsoPQlmGdgpFfmAsiYrnYFXLTHgbgCc/YhV8lubTakUdI3bMYWfh9dkj+DVGUmt2gLtQUzbuH8EU44vnXgrQYSXNQkmRcyoE3rj4Rhhbu/p5D3P+nuOukLYFOLRaNeiiGyTu3P7gtc/dy/UjUrf+pH75UUU7Lb369dGEfZwvVtITXsdyp0pBfun4CP808H9N0CAwEAAaOBwTCBvjAdBgNVHQ4EFgQUP5smx3ZYKODMkDglkTbduvLcGYAwgY4GA1UdIwSBhjCBg4AUP5smx3ZYKODMkDglkTbduvLcGYChYKReMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEhMB8GA1UEChMYVW5pdmVyc2l0eSBvZiBXYXNoaW5ndG9uMR0wGwYDVQQDExRpZHAudS53YXNoaW5ndG9uLmVkdYIJAMoYJbDt9lKKMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAEo7c2CNHEI+Fvz5DhwumU+WHXqwSOK47MxXwNJVpFQ9GPR2ZGDAq6hzLJLAVWcY4kB3ECDkRtysAWSFHm1roOU7xsU9f0C17QokoXfLNC0d7KoivPM6ctl8aRftU5moyFJkkJX3qSExXrl053uxTOQVPms4ypkYv1A/FBZWgSC8eNoYnBnv1Mhy4m8bfeEN7qT9rFoxh4cVjMH1Ykq7JWyFXLEB4ifzH4KHyplt5Ryv61eh6J1YPFa2RurVTyGpHJZeOLUIBvJu15GzcexuDDXe0kg7sHD6PbK0xzEF/QeXP/hXzMxR9kQXB/IR/b2k4ien+EM3eY/ueBcTZ95dgVM=';
const uwIdPEntryPoint = 'https://idp.u.washington.edu/idp/profile/SAML2/Redirect/SSO';
const strategyName = 'uwsaml';

//standard login, callback, logout, and meta-data URLs
//these will be exposed from module.exports so that
//clients can refer to them
//the metadata one in particular is important to get right
//as the auto-regisration process requires that exact URL
const urls = {
    metadata: '/Shibboleth.sso/Metadata',
    uwLogoutUrl: 'https://idp.u.washington.edu/idp/logout'
};

//export the urls map
module.exports.urls = urls;

//map of possible profile attributes and what name
//we should give them on the resulting user object
//add to this with other attrs if you request them
const profileAttrs = {
    'urn:oid:0.9.2342.19200300.100.1.1': 'netId',
    'urn:oid:2.16.840.1.113730.3.1.241': 'displayName',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': 'affiliation',
    'urn:oid:2.5.4.3': 'cn',
    'urn:oid:0.9.2342.19200300.100.1.3': 'email',
    'urn:oid:2.16.840.1.113730.3.1.3': 'empNum',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'principalName',
    'urn:oid:2.5.4.42': 'givenName',
    'urn:oid:2.5.4.18': 'box',
    'urn:oid:2.5.4.20': 'phone',
    'urn:oid:2.5.4.4': 'surname',
    'urn:oid:2.5.4.12': 'title',
    'urn:oid:1.2.840.113994.200.21': 'studentId',
    'urn:oid:1.2.840.113994.200.24': 'regId'
};

function convertProfileToUser(profile) {
    var user = {};
    var niceName;
    var attr;
    for (attr in profile) {
        niceName = profileAttrs[attr];
        if (niceName !== undefined && profile[attr]) {
            user[niceName] = profile[attr];
        }
    }

    return user;    
}

/*
    Passport Strategy for UW Shibboleth Authentication
    This class extends passport-saml's Strategy, providing the necessary 
    options and handling the conversion of the returned profile into a 
    sensible user object.

    options should contain:
        entityId: your server's entity id,
        domain: your server's domain name,
        callbackUrl: login callback url (relative to domain),
        privateKey: your private key for signing requests (optional)
*/
function Strategy(options) {
    samlOptions = {
        entryPoint: uwIdPEntryPoint,
        cert: uwIdPCert,
        identifierFormat: null,
        issuer: options.entityId || options.domain,
        callbackUrl: 'https://' + options.domain + options.callbackUrl,
        decryptionPvk: options.privateKey,
        privateCert: options.privateKey
    };

    function verify(profile, done) {
        if (!profile)
            return done(new Error('Empty SAML profile returned!'));
        else        
            return done(null, convertProfileToUser(profile));                
    }

    saml.Strategy.call(this, samlOptions, verify);
    this.name = strategyName;
}

util.inherits(Strategy, saml.Strategy);

//expose the Strategy
module.exports.Strategy = Strategy;

/*
    Route implementation for the standard Shibboleth metadata route
    usage:
        var uwshib = require(...);
        var strategy = new uwshib.Strategy({...});
        app.get(uwshib.urls.metadata, uwshib.metadataRoute(strategy, myPublicCert));
*/
module.exports.metadataRoute = function(strategy, publicCert) {
    return function(req, res) {
        res.type('application/xml');
        res.send(200, strategy.generateServiceProviderMetadata(publicCert));
    }
} //metadataRoute

/*
    Middleware for ensuring that the user has authenticated.
    You can use this in two different ways. If you pass this to
    app.use(), it will secure all routes added after that.
    Or you can use it selectively on routes that require authentication
    like so:
        app.get('/foo/bar', ensureAuth(loginUrl), function(req, res) {
            //route implementation
        });

    where loginUrl is the url to your login route where you call
    passport.authenticate()
*/
module.exports.ensureAuth = function(loginUrl) {
    return function(req, res, next) {
        if (req.isAuthenticated())
            return next();
        else {
            req.session.authRedirectUrl = req.url;
            res.redirect(loginUrl);            
        }
    }
};

/*
    Middleware for redirecting back to the originally requested URL after
    a successful authentication. The ensureAuth() middleware above will
    capture the current URL in session state, and when your callback route
    is called, you can use this to get back to the originally-requested URL.
    usage:
        var uwshib = require(...);
        var strategy = new uwshib.Strategy({...});
        app.get('/login', passport.authenticate(strategy.name));
        app.post('/login/callback', passport.authenticate(strategy.name), uwshib.backtoUrl());
        app.use(uwshib.ensureAuth('/login'));
*/
module.exports.backToUrl = function(defaultUrl) {
    return function(req, res) {
        var url = req.session.authRedirectUrl;
        delete req.session.authRedirectUrl;
        res.redirect(url || defaultUrl || '/');
    }
};

