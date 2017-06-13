const _ = require('lodash');
const fs = require('fs');
const Handlebars = require('handlebars');
const uuid = require('uuid');

const ERR_UNKNOWN = "UNKNOWN ERROR";
const ERR_UNAUTHORIZED = "UNAUTHORIZED";

module.exports = (r, email, _settings) => {
  
  const settings = _.merge({    
    site: {
      name: 'NAME THIS SITE!',                                          // used for templates
      url: 'http://localhost:8000'                                      // used for link generation
    },
    emails: {
      passwordReset: {
        subject: 'Please confirm your password reset request',
        template: Handlebars.compile(fs.readFileSync(__dirname + '/templates/password_reset.html', 'utf-8'))
      }
    }
  }, _settings);

  const notify = (req) => {
    return (user) => {
      return new Promise((resolve, reject) => {
        const data = {
          params: user,
          site: {
            name: settings.site.name
          },
          reset_link: `${settings.site.url}${req.baseUrl}/password_reset_confirm?token=${user.perishableToken}&redirect_to=${settings.site.url}`
        };
        const html = settings.emails.passwordReset.template(data);
        const message = {
          text: "",
          from: settings.email.from,
          subject: settings.emails.passwordReset.subject,
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
  };

  const fetch = (params) => {
    return r
      .table('users')
      .getAll(params.email, { index: 'email' })
      .then((results) => {
        if (results.length == 1) {
          return results[0];
        } else {
          throw new Error(ERR_UNAUTHORIZED);
        }
      });
  };

  const setPerishableToken = (user) => {
    user.perishableToken = uuid.v4();
    return r
      .table('users')
      .get(user.id)
      .update({
        perishableToken: user.perishableToken
      })
      .then((result) => {
        return user;
      });
  };

  return (req, res) => {
    fetch(req.query)
      .then(setPerishableToken)
      .then(notify(req))
      .then((user) => {
        res.send({ success: true, message: "Reset request sent" });
      })
      .catch((error) => {
        if (error) console.error(error);
        res.status(500).send(ERR_UNKNOWN);
      });
  };

}