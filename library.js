/**
 * Created by holly on 16/3/30.
 */
"use strict";
var request = module.parent.require("request");
var User = module.parent.require("./user"),
    Password = module.parent.require("../password"),
    utils = module.parent.require("../../public/src/utils"),
    db = module.parent.require('./database'),
    passport = module.parent.require("passport"),
    passportLocal = module.parent.require('passport-local').Strategy,
    nconf = module.parent.require("nconf"),
    async = module.parent.require("async"),
    freebackingSite = nconf.get("freebackingSite"),
    reqSmsUrl = nconf.get("reqSmsUrl"),
    signinUrl = nconf.get("signinUrl");
(function (module) {
    //通过手机号登录 第一次发送验证码登录
    var AuthOverrideLogin = {};
    AuthOverrideLogin.auth = function(data,callback){
        passport.use(new passportLocal({passReqToCallback: true}, signinWithCode));

    };

    module.exports = AuthOverrideLogin;
})(module);

//获取验证码
function getSmsCode(body, callback) {
    request.post(reqSmsUrl, {baseUrl: freebackingSite, json: true, body: body}, function (err, msg, res) {

    });

};

//根据手机号 验证码登录
//首次登录需要在平台创建一个用户,之后登录则验证用户存在即可
function signinWithCode(req, username, password, next) {
    if (!username) {
        return next(new Error('[[error:invalid-username]]'));
    }
    var userslug = utils.slugify(username);
    var uid, userData = {};

    async.waterfall([
        function (next) {
            User.isPasswordValid(password, next);
        },
        function (next) {
            User.getUidByUserslug(userslug, next);
        },
        function (_uid, next) {
            if (!_uid) {
                return next(new Error('[[error:no-user]]'));
            }
            uid = _uid;
            User.auth.logAttempt(uid, req.ip, next);
        },
        function (next) {
            async.parallel({
                userData: function(next) {
                    db.getObjectFields('user:' + uid, ['password', 'banned', 'passwordExpiry'], next);
                },
                isAdmin: function(next) {
                    User.isAdministrator(uid, next);
                }
            }, next);
        },
        function (result, next) {
            userData = result.userData;
            userData.uid = uid;
            userData.isAdmin = result.isAdmin;

            if (!result.isAdmin && parseInt(meta.config.allowLocalLogin, 10) === 0) {
                return next(new Error('[[error:local-login-disabled]]'));
            }

            if (!userData || !userData.password) {
                return next(new Error('[[error:invalid-user-data]]'));
            }
            if (userData.banned && parseInt(userData.banned, 10) === 1) {
                return next(new Error('[[error:user-banned]]'));
            }
            Password.compare(password, userData.password, next);
        },
        function (passwordMatch, next) {
            if (!passwordMatch) {
                return next(new Error('[[error:invalid-password]]'));
            }
            User.auth.clearLoginAttempts(uid);
            next(null, userData, '[[success:authentication-successful]]');
        }
    ], next);
    /*request.post(signinUrl, {baseUrl: freebackingSite, json: true, body:body}, function (err, msg, res) {


    });*/

};