const ERR_UNAUTHORIZED = "UNAUTHORIZED";
const ERR_INVALID_PARAMS = "INVALID PARAMETERS";
const ERR_CRYPTO = "CRYPTO ERROR";

const Token = require('./token');
const validateParams = require('./validate_params');
const bcrypt = require('bcrypt');

module.exports = (r, settings) => {

  const fetch = (email) => r
    .table('users')
    .getAll(email, { index: 'email' })
    .without('perishableToken')
    .limit(1)      
    .map((user) => {
      if (settings.multitenancy) {
        return {
          user: user,
          organization: r.table('organizations').get(user('organization_id'))
        };
      } else {
        return {
          user: user
        };
      }
    })
    .then((results) => {
      if (results.length == 1) {
        return results[0];
      } else {
        return null;
      }
    });
  

  const authorize = (params) => {
    return (auth) => {
      return new Promise((resolve, reject) => {
        if (auth) {          
          bcrypt.compare(params.password, auth.user.password, (error, valid) => {            
            if (error) {
              reject(new Error(ERR_CRYPTO));
            } else {
              if (valid) {
                delete auth.user.password;
                delete auth.user.perishableToken;
                resolve(auth);
              } else {
                reject(new Error(ERR_UNAUTHORIZED));
              }
            }
          });
        } else {
          reject(new Error(ERR_UNAUTHORIZED));
        }
      });
    };
  };

  const createToken = (auth) => {
    return new Promise((resolve, reject) => {
      const organization_id = settings.multitenancy ? auth.organization.id : undefined;
      auth.token = Token(settings, auth.user.id, organization_id).encode();
      resolve(auth);
    });
  };

  this.login = (req, res) => {
    const params = req.body;
    if (validateParams(params, ['email', 'password'])) {
      fetch(params.email)
        .then(authorize(params))
        .then(createToken)
        .then((auth) => {
          res.send(auth);
        })
        .catch((error) => {          
          res.status(403).send(error.message);
        });
    } else {
      res.status(500).send(ERR_INVALID_PARAMS);
    }
  };

  return this.login;
};