const passwordGenerator = require('generate-password');
const bcrypt = require('bcrypt');
const _ = require('lodash');
const fs = require('fs');
const Handlebars = require('handlebars');

const ERR_PASSWORD_GENERATION = 'Password generation error';
const ERR_UNKNOWN = "UNKNOWN ERROR";
const ERR_UNAUTHORIZED = "UNAUTHORIZED";

module.exports = (r, email, settings) => {

  const generatePassword = (user) => {
    return new Promise((resolve, reject) => {
      const password = passwordGenerator.generate({ 
        length: 10, 
        numbers: true, 
        symbols: true, 
        excludeSimilarCharacters: true 
      });
      
      bcrypt.hash(password, 13, (error, hash) => {
        if (error) {
          reject(new Error(ERR_PASSWORD_GENERATION));
        } else {
          user.password = password;
          r.table('users')
           .get(user.id)
           .update({
             password: hash,
             perishableToken: null
           })
           .then((result) => {
             resolve(user);
           });
        }
      });
    });
  };

  const notify = (user) => {
    return new Promise((resolve, reject) => {
      const data = {
        params: user,
        site: {
          name: settings.site.name
        }
      };
      const html = settings.emails.passwordResetConfirm.template(data);
      const message = {
        text: "",
        from: settings.email.from,
        subject: settings.emails.passwordResetConfirm.subject,
        to: user.email,
        attachment: [
          { data: html, alternative: true }
        ]
      };
      email.send(message, (error, message) => {
        if (error) {
          reject(new Error(ERR_EMAIL_NOTIFICATION));
        } else {
          resolve(user);
        }
      });
    });    
  };

  const fetch = (params) => {
    return r
      .table('users')
      .getAll(params.token, { index: 'perishableToken' })
      .then((results) => {
        if (results.length == 1) {
          return results[0];
        } else {
          return null;
        }
      });
  };

  return (req, res) => {
    fetch(req.query)
      .then((user) => {
        if (user) {
          return user;
        } else {
          throw new Error(ERR_UNAUTHORIZED);
        }
      })
      .then(generatePassword)
      .then(notify)
      .then((user) => {
        res.send({ success: true, message: "Password has been reset" });
      })
      .catch((error) => {
        res.status(500).send(ERR_UNKNOWN);
      });
  };

}