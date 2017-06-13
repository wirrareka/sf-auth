const bcrypt = require('bcrypt');
const Handlebars = require('handlebars');
const fs = require('fs');
const uuid = require('uuid');
const _ = require('lodash');
const validateParams = require('./validate_params');

const ERR_INVALID_PARAMS = 'Invalid Parameters';
const ERR_ORGANIZATION_NOT_UNIQUE = 'Organization is not unique';
const ERR_USER_NOT_UNIQUE = 'User is not unique';
const ERR_PASSWORD_GENERATION = 'Password generation error';
const ERR_EMAIL_NOTIFICATION = 'Email notification error';

module.exports = (r, email, settings) => {

  const checkUniqueOrganization = (params) => {
    if (settings.multitenancy) {
      return r
        .table('organizations')
        .getAll(params.organization.name, { index: 'name' })
        .then((result) => {
          if (Array.isArray(result) && result.length > 0) {
            throw new Error(ERR_ORGANIZATION_NOT_UNIQUE);
          } else {
            return params;
          }
        });
    } else {
      return new Promise((resolve) => resolve(params));
    }
  };

  const checkUniqueUser = (params) => {
    return r
      .table('users')
      .getAll(params.user.email, {index: 'email'})
      .then((result) => {
        if (Array.isArray(result) && result.length > 0) {
          throw new Error(ERR_USER_NOT_UNIQUE);
        } else {
          return params;
        }
      });
  };
  
  const createOrganization = (params) => {
    if (settings.multitenancy) {
      return r
        .table('organizations')
        .insert(params.organization)
        .then((result) => {
          params.organization.id = result.generated_keys[0];        
          return params;
        });      
    } else {
      return new Promise((resolve) => resolve(params));
    }
  };

  const createUser = (params) => {
    // add perishable token for email confirmation    
    params.user.perishableToken = uuid.v4();
    params.user.emailConfirmed = false;
    params.user.role = 'superuser';

    if (settings.multitenancy) {
      params.user.organization_id = params.organization.id;
    }

    return r
      .table('users')
      .insert(params.user)
      .then((result) => {
        params.user.id = result.generated_keys[0];
        return params;
      });
  };

  const encryptPassword = (params) => {
    return new Promise((resolve, reject) => {
      bcrypt.hash(params.user.password, 13, (err, hash) => {
        if (err) {          
          reject(new Error(ERR_PASSWORD_GENERATION));
        } else {
          delete params.user.passwordConfirmation;
          delete params.user.perishableToken;
          params.user.password = hash; 
          resolve(params);
        }
      });
    });
  };

  const notify = (req) => {  
    return (params) => {
      return new Promise((resolve, reject) => {
        const data = {
          params: params,
          site: {
            name: settings.site.name
          },
          activation_link: `${settings.site.url}${req.baseUrl}/activate?token=${params.user.perishableToken}&redirect_to=${settings.site.url}`
        };
        const html = settings.emails.confirm.template(data);
        const message = {
          text: "",
          from: settings.email.from,
          subject: settings.emails.confirm.subject,
          to: params.user.email,
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
  };

  const validateRegistration = (params) => {
    const organizationValid = settings.multitenancy ? validateParams(params.organization, ['name']) : true;
    return  organizationValid &&
            validateParams(params.user, ['firstName', 'lastName', 'email', 'password', 'passwordConfirmation']) &&
            params.user.password == params.user.passwordConfirmation;
  };

  this.register = (req, res) => {
    const required = ['user'];

    if (settings.multitenancy) {
      required.push('organization');
    }

    if (validateParams(req.body, required)) {
      const params = req.body;
      params.user.createdAt = new Date();
      params.user.updatedAt = new Date();

      if (settings.multitenancy) {
        params.organization.createdAt = new Date();
        params.organization.updatedAt = new Date();
      }

      if (validateRegistration(params)) {
        checkUniqueOrganization(params)
          .then(checkUniqueUser)
          .then(encryptPassword)
          .then(createOrganization)
          .then(createUser)
          .then(notify(req))
          .then((params) => {
            delete params.user.password;
            delete params.user.perishableToken;
            res.send(params);
          })
          .catch((error) => {            
            res.status(500).send(error.message);
          });
      } else {
        res.status(500).send(ERR_INVALID_PARAMS);
      }
    } else {
      res.status(500).send(ERR_INVALID_PARAMS);
    }
  };

  return this.register;
};
