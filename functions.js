var bcrypt = require('bcryptjs'),
    Q = require('q'),
    config = require('./config.js'), 
    db = require('orchestrate')(config.db); 

exports.localReg = function (username, password) {
  var deferred = Q.defer();
  var hash = bcrypt.hashSync(password, 8);
  var user = {
    "username": username,
    "password": hash,
    "avatar": "https://www.facebook.com/profile/pic.php?cuid=AYjoQdIzRAROT3K5NgsGSHjMDmppxqCxUNActRI14u5JB3YsFu6uqpMWg6QnLG-vxOrbd_BAU3jy8OOhU36-IERH6eqRucu9iWEYSBgWCANPa0BmkaiRBuIC_M8JSoZWCn_mKFYb5xDzPvzpkdl3EyHtcp75gGn8NFSt_KkFraSWiySQ8gtFs7xnEHhgKC2_5nmzJruN6J0rhn38eNgx377pwS2_zjDfS7ah471YNAncRbMSY2J-8xMh8pELIGLOb8o&square_px=64"
  }
 
  db.get('local-users', username)
  .then(function (result){ 
    console.log('username already exists');
    deferred.resolve(false); 
  })
  .fail(function (result) {
      console.log(result.body);
      if (result.body.message == 'The requested items could not be found.'){
        console.log('Username is free for use');
        db.put('local-users', username, user)
        .then(function () {
          console.log("USER: " + user);
          deferred.resolve(user);
        })
        .fail(function (err) {
          console.log("PUT FAIL:" + err.body);
          deferred.reject(new Error(err.body));
        });
      } else {
        deferred.reject(new Error(result.body));
      }
  });

  return deferred.promise;
};


exports.localAuth = function (username, password) {
  var deferred = Q.defer();

  db.get('local-users', username)
  .then(function (result){
    console.log("FOUND USER");
    var hash = result.body.password;
    console.log(hash);
    console.log(bcrypt.compareSync(password, hash));
    if (bcrypt.compareSync(password, hash)) {
      deferred.resolve(result.body);
    } else {
      console.log("PASSWORDS NOT MATCH");
      deferred.resolve(false);
    }
  }).fail(function (err){
    if (err.body.message == 'The requested items could not be found.'){
          console.log("COULD NOT FIND USER IN DB FOR SIGNIN");
          deferred.resolve(false);
    } else {
      deferred.reject(new Error(err));
    }
  });

  return deferred.promise;
}