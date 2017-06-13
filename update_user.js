const validateParams = require('./validate_params');

const ERR_EMAIL_NOT_UNIQUE = "EMAIL IS NOT UNIQUE";
const ERR_INVALID_PARAMS = "INVALID PARAMETERS";

module.exports = (r) => {
  return (req, res) => {
    const params = req.body;
    if (validateParams(params, [ "email" ])) {
      delete params.password;
      delete params.passwordConfirmation;
      delete params.createdAt;
      delete params.organization_id;
      params.updatedAt = new Date();
      r.table('users')
        .get(req.params.id)
        .update(params)
        .then((result) => {
          r.table('users')
           .get(req.params.id)
           .without(['password', 'passwordConfirmation', 'perishableToken'])
           .then((response) => {
            res.send(response);
           });
        })
        .catch((error) => {
          res.status(500).send(error.message);
        });
    } else {
      res.status(500).send(ERR_INVALID_PARAMS);
    }
  };
};