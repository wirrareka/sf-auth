const Token = require('./token');

const ERR_UNAUTHORIZED = "UNAUTHORIZED";
const ERR_UNKNOWN = "UNKNOWN ERROR";

module.exports = (r, settings) => {

  return (req, res, next) => {
    if (req.headers.authorization === undefined) {
      res.status(403).send(ERR_UNAUTHORIZED);
      return;
    }
    
    const split = req.headers.authorization.split(' ');

    if (split.length != 2) {
      res.status(403).send(ERR_UNAUTHORIZED);
      return;
    }

    const encoded = split[1];
    const token = Token.decode(settings, encoded);
    r.table('users')
      .getAll(token.payload.user_id)
      .without('password', 'passwordConfirmation', 'perishableToken')
      .map((doc) => {
        const object = {
          user: doc
        };

        if (settings.multitenancy)
          object.organization = r.table('organizations').get(doc('organization_id'));

        return object;
      })
      .then((auth) => {
        req.auth = auth[0];
        res.set('Token-Exchange', token.encode());
        next();
      })
      .catch((error) => {
        console.log('error', error);
        res.status(403).send(ERR_UNAUTHORIZED);
      });
  };
};