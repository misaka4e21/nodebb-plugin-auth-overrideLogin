/**
 * Created by holly on 16/3/30.
 */
"use strict";
var User = module.parent.require("./user"),
    Password = module.parent.require("./password"),
    utils = module.parent.require("../public/src/utils"),
    db = module.parent.require('./database'),
    passport = module.parent.require("passport"),
    passportLocal = module.parent.require('passport-local').Strategy,
    nconf = module.parent.require("nconf"),
    request = module.parent.require("request"),
    async = module.parent.require("async"),
    meta = module.parent.require('./meta'),
    freebackingSite = nconf.get("freebackingSite"),
    reqSmsUrl = nconf.get("reqSmsUrl"),
    signinUrl = nconf.get("signinUrl"),
    const_pwd = nconf.get("const_pwd");
(function (module) {
    //通过手机号登录 第一次发送验证码登录
    var AuthOverrideLogin = {};
    AuthOverrideLogin.load = function (arg, next) {
        var app = arg.app;
        var router = arg.router;
        var middleware = arg.middleware;
        var controllers = arg.controllers;
        //挂载路由 调用接口发送短信
        //console.log('arguments22:',arguments);
        router.post("/api/reqSms", function (req, res) {
            var phone = req.body.phone;
            if (!phone || !/(13|14|15|17|18)[0-9]{9}/.test(phone)) {
                res.json({err: 400});
                return;
            }
            getSmsCode({pno: phone}, function (err) {
                if (err) {
                    res.json({err: 401, text: err.text});
                    return;
                }
                res.json({err: 200});
            });

        });
        app.use(router);

    };
    AuthOverrideLogin.auth = function () {
        passport.use(new passportLocal({passReqToCallback: true}, signinWithCode));
    };


    module.exports = AuthOverrideLogin;
})(module);

//获取验证码
function getSmsCode(body, callback) {
    request({
            method: 'POST',
            url: reqSmsUrl,
            baseUrl: freebackingSite,
            json: true,
            body: body
        },
        function (err, msg, res) {
            console.log('res65:', res);
            if (err) {
                callback(err);
                return;
            }
            if (msg.statusCode !== 200) {
                callback(msg.statusMessage);
                return;
            }
            if (res.r && res.r.code === 504) { //发送成功
                callback();
                return;
            }
            callback(res.r);

        });
};


function signIn(body, callback) {
    console.log('signIn........');
    request({
        method: 'POST',
        url: signinUrl,
        baseUrl: freebackingSite,
        json: true,
        body: body
    }, function (err, msg, res) {
        if (err) {
            callback(err);
            return;
        }
        console.log('statusCode:', msg.statusCode);
        if (msg.statusCode !== 200) {
            callback(msg.statusMessage);
            return;
        }
        console.log("res:", res);
        if (!res.profile) {
            console.log('the user not exists!');
            callback('user not exists');
            return;
        }
        //读取手机号 userID id avatar nick
        var user = {
            id: res.profile.id,
            userID: res.profile.userID,
            nick: res.profile.nick,
            avatar: res.profile.avatar
        };
        console.log('user:', user);
        callback(null, user);
    });
}


function signinWithUserName(req, username, password, next) {//用户名登录
    var userslug = utils.slugify(username);
    var uid, userData = {};
    async.waterfall([
        function (next) {
            User.isPasswordValid(password, next);
        }, function (next) {
            User.getUidByUserslug(userslug, next);
        }, function (_uid, next) {
            uid = _uid;
            User.auth.logAttempt(uid, req.ip, next);
        }, function (next) {
            async.parallel({
                userData: function (next) {
                    db.getObjectFields('user:' + uid, ['password', 'banned', 'passwordExpiry'], next);
                },
                isAdmin: function (next) {
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
        }], next);

};

function signinWithPhone(req, username, password, next) {//手机号登录
    console.log("signinWithPhone......");
    console.log("username171:",username);
    console.log("password172:",password);
    var uid, userData = {};
    async.waterfall([
        function (next) {
            //判断验证码为6位数字
            if (/\d{6}/.test(password)) {
                console.log("Prepare signIn......");
                signIn({pno: username, smsCode: password}, function (err,user) {
                    if(err){
                        console.log('err177:',err);
                        return next(new Error(err.text));
                    }
                    next(null,user);
                });
            } else {
                console.log("The code is not six number");
                next(new Error("The code is not six number"));
            }
        }, function (user, next) {
            console.log("user181:", user);
            //此时username 就是phone
            //通过phone拿到uid
            User.getUidByPhone(username, function (err, _uid) {
                next(err, _uid, user);
            });

        }, function (_uid, user, next) {
            //通过uid 拿到username
            console.log('_uid189:',_uid);
            if (_uid) {
                uid = _uid;
                User.getUsernamesByUids([_uid], function (err, users) {
                    next(err, users, user);
                });
            } else {
                //
                next(null, null, user);
            }

        }, function (users, user, next) {
            console.log("users201:", users);
            console.log("user202:", user);
            var uname;
            if (!users || !users.length) { //系统里没有这个用户则创建
                //uname = user.userID;
                //uname 替换为profile.id 保持4位,不足4位前面补0
                var userId = ''+user.id;
                uname = '0000'.slice(userId.length)+userId;
                User.create({
                    username: uname,
                    password: const_pwd,
                    fullname: user.nick,
                    phone: username
                }, function (err, _uid) {
                    if (err) {
                        return next(new Error('[[error:no-user]]'));
                    }
                    uid = _uid;
                    User.auth.logAttempt(uid, req.ip, next);
                    //next();
                });
            } else {
                uname = users[0];
                User.auth.logAttempt(uid, req.ip, next);
                //next()
            }

        }, function (next) {
            async.parallel({
                userData: function (next) {
                    db.getObjectFields('user:' + uid, ['password', 'banned', 'passwordExpiry'], next);
                },
                isAdmin: function (next) {
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
            //Password.compare(password, userData.password, next);
            Password.compare(const_pwd, userData.password, next);
        },
        function (passwordMatch, next) {
            if (!passwordMatch) {
                return next(new Error('[[error:invalid-password]]'));
            }
            User.auth.clearLoginAttempts(uid);
            next(null, userData, '[[success:authentication-successful]]');
        }], next);

};
//根据手机号 验证码登录
//首次登录需要在平台创建一个用户,之后登录则验证用户存在即可
function signinWithCode(req, username, password, next) {
    console.log("username:", username);
    console.log("password:", password);
    if (!username) {
        return next(new Error('[[error:invalid-username]]'));
    }
    //var userslug = utils.slugify(username);
    //var uid, userData = {};
    //正则判断 手机号还是用户ID
    if (/(13|14|15|17|18)[0-9]{9}/.test(username)) {  //手机号登录
        return signinWithPhone(req, username, password, next);
    } else { //用户名登录
        return signinWithUserName(req, username, password, next);
    }

    /*
     async.waterfall([
     function (next) {
     User.isPasswordValid(password, next);
     },
     function (next) {
     User.getUidByUserslug(userslug, next);
     },
     function (_uid, next) {
     console.log("_uid=============:", _uid);
     if (!_uid) {
     //如果不存在,则请求接口验证 手机号验证码
     async.waterfall([
     function (next) {
     signIn({pno: username, smsCode: password}, next);
     },
     function (user, next) {
     User.create({username: username, password: const_pwd, fullname: user.nick}, next);

     }], function (err, __uid) {
     if (err) {
     return next(new Error('[[error:no-user]]'));
     }
     uid = __uid;
     password = const_pwd; //手机用户统一修改密码为常量
     User.auth.logAttempt(uid, req.ip, next);
     //return;
     });
     //return next(new Error('[[error:no-user]]'));
     } else if (_uid !== 1) { //存在 若非管理员 则手机号验证登录
     signIn({pno: username, smsCode: password}, function (err, user) {
     if (err) {
     return next(new Error('[[error:no-user]]'));
     }
     uid = _uid;
     password = const_pwd; //手机用户统一修改密码为常量
     User.auth.logAttempt(uid, req.ip, next);
     //return;
     });
     } else {
     uid = _uid;
     User.auth.logAttempt(uid, req.ip, next);
     }

     },
     function (next) {
     async.parallel({
     userData: function (next) {
     db.getObjectFields('user:' + uid, ['password', 'banned', 'passwordExpiry'], next);
     },
     isAdmin: function (next) {
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
     */
};