const validateParams = require('./validate_params');
const ERR_EMAIL_NOT_UNIQUE = "EMAIL IS NOT UNIQUE";
const ERR_INVALID_PARAMS = "INVALID PARAMETERS";
const bcrypt = require('bcrypt');

module.exports = (r, settings) => {
  return (req, res) => {
    const params = req.body;
    if (validateParams(params, ["firstName", "lastName", "email", "password", "passwordConfirmation" ]) &&
        params.password === params.passwordConfirmation) {
      r.table('users')
        .getAll(params.email, { index: 'email' })
        .then((results) => {
          if (results.length === 0) {
            const user = params;
            const date = new Date();
            user.perishableToken = null;
            user.emailConfirmed = false;
            user.createdAt = date;
            user.updatedAt = date;
            user.role = 'user';

            if (settings.multitenancy) {
              user.organization_id = req.auth.organization.id;
            }

            delete user.passwordConfirmation;
            bcrypt.hash(user.password, 13, (error, hash) => {              
              user.password = hash;
              r.table('users')
               .insert(user)
               .then((result) => {
                 user.id = result.generated_keys[0];
                 delete user.password;
                 delete user.perishableToken;
                 res.send(user);
               });
            });
          } else {
            res.status(403).send(ERR_EMAIL_NOT_UNIQUE);
          }
        });
    } else {
      res.status(500).send(ERR_INVALID_PARAMS);
    }
  };
};