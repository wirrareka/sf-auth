const _ = require('lodash');

const ERR_MISSING_TOKEN = 'Missing token';
const ERR_INVALID_TOKEN = 'Invalid token';

module.exports = (r, email, settings) => {

  const notify = (params) => {
    return new Promise((resolve, reject) => {
      const data = {
        params: params,
        site: {
          name: settings.site.name
        }
      };
      const html = settings.emails.active.template(data);
      const message = {
        text: "",
        from: settings.email.from,
        subject: settings.emails.active.subject,
        to: params.email,
        attachment: [
          { data: html, alternative: true }
        ]
      };
      email.send(message, (error, message) => {
        if (error) {
          reject(new Error(ERR_EMAIL_NOTIFICATION));
        } else {          
          resolve(params);
        }
      });
    });    
  };

  const fetch = (token) => {    
    return r
      .table('users')
      .getAll(token, { index: 'perishableToken' })
      .then((results) => {        
        if (results.length == 1) {
          return results[0];
        } else {
          throw new Error(ERR_INVALID_TOKEN);
        }
      });
  };

  const confirm = (user) => {
    const updatedAt = new Date();

    return r
      .table('users')
      .get(user.id)
      .update({
        emailConfirmed: true,
        perishableToken: null,
        updatedAt: updatedAt
      })
      .then((result) => {        
        user.emailConfirmed = true;
        user.perishableToken = null;
        user.updatedAt = updatedAt;
        return user;
      });
  };

  return (req, res) => {
    if (req.query.token === undefined) {
      res.status(500).send(ERR_MISSING_TOKEN);
    } else {
      fetch(req.query.token)
        .then(confirm)
        .then(notify)
        .then((user) => {
          const redirect = req.query.redirect_to || '/';
          res.redirect(redirect);
        })
        .catch((error) => {
          res.status(403).send(ERR_INVALID_TOKEN);
        });
    }    
  };

};