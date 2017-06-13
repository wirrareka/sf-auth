const bcrypt = require('bcrypt');
const _ = require('lodash');

const ERR_PASSWORD_GENERATION = 'Password generation error';
const ERR_UNKNOWN = "UNKNOWN ERROR";
const ERR_UNAUTHORIZED = "UNAUTHORIZED";

module.exports = (r, email, settings) => {

  const notify = (user) => {
    return new Promise((resolve, reject) => {
      const data = {
        params: user,
        site: {
          name: settings.site.name
        }
      };
      const html = settings.emails.passwordChange.template(data);
      const message = {
        text: "",
        from: settings.email.from,
        subject: settings.emails.passwordChange.subject,
        to: user.email,
        attachment: [
          { data: html, alternative: true }
        ]
      };
      email.send(message, (error, message) => {
        if (error) {
          console.error(error);
          reject(new Error(ERR_EMAIL_NOTIFICATION));
        } else {
          resolve(user);
        }
      });
    });    
  };

  const verifyPassword = (params) => {
    return (user) => {
      return new Promise((resolve, reject) => {
        bcrypt.compare(params.currentPassword, user.password, (error, valid) => {
          if (error || !valid) {            
            reject(new Error(ERR_UNAUTHORIZED));
          } else {            
            resolve(user);
          }
        });
      });
    };
  };

  const changePassword = (params) => {
    return (user) => {
      return new Promise((resolve, reject) => {
        if (params.newPassword.length <=6) {
          reject(new Error(ERR_UNAUTHORIZED));
        } else {
          bcrypt.hash(params.newPassword, 13, (err, hash) => {            
            r.table('users')
            .get(user.id)
            .update({
              password: hash,
              updatedAt: new Date()
            })
            .then((result) => {
              resolve(user);
            })
            .catch(reject);
          });
        }
      });
    };
  };
  
  const fetch = (user) => {
    return r
      .table('users')
      .get(user.id);
  };

  return (req, res) => {
    const params = req.body;    
    fetch(req.auth.user)
      .then(verifyPassword(params))
      .then(changePassword(params))
      .then(notify)
      .then((user) => {
        res.send({ success: true, message: "Password has been changed" });
      })
      .catch((error) => {
        console.error(error);
        res.status(500).send(ERR_UNKNOWN);
      });
  };

};