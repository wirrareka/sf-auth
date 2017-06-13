const ERR_UNAUTHORIZED = "UNAUTHORIZED";
const ERR_INVALID_PARAMS = "INVALID PARAMETERS";
const ERR_CRYPTO = "CRYPTO ERROR";

const jwt = require('jwt-simple');
const validateParams = require('./validate_params');
const bcrypt = require('bcrypt');

module.exports = (r, settings) => {

  const fetch = (user, organization_id) => {
    if (settings.multitenancy) {
      return r
        .table('organizations')
        .get(organization_id)
        .then((organization) => {
          return {
            user: user,
            organization: organization
          };
        });    
    } else {
      return {
        user: user
      };
    }
  };

  const authorize = (params) => {
    return (auth) => {
      return new Promise((resolve, reject) => {
        if (auth) {          
          bcrypt.compare(params.password, auth.user.password, (error, valid) => {            
            if (error) {
              console.error(error);
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
    const date = new Date();

    const payload = {
      user_id: auth.user.id,
      organization_id: auth.organization.id,
      issued_at: date.getTime()
    };

    if (settings.multitenancy) {
      payload.organization_id = auth.organization_id;
    }
    
    auth.token = jwt.encode(payload, settings.secret);

    const token = {
      createdAt: date,
      token: auth.token,
      user_id: auth.user.id,
      usageCount: 0,
      lastUsed: date 
    };

    if (settings.multitenancy) {
      token.organization_id = auth.organization_id;
    }

    return r
      .table('tokens')
      .insert(token)
      .then((result) => {
        token.id = result.generated_keys[0];
        return auth;
      });
  };

  this.login = (req, res) => {
    const params = req.body;
    const required = settings.multitenancy ? ['organization_id'] : [];
    if (validateParams(params, required)) {
      fetch(req.auth.user, params.organization_id)
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