const jwt = require('jwt-simple');

const ERR_EXPIRED = "TOKEN EXPIRED";

const Token = (settings, user_id, organization_id) => {
  
  let secret = settings.secret;
  let expiration = settings.tokenExpiration;

  this.payload = {
    user_id: user_id      
  };

  if (settings.multitenant) {
    this.payload.organization_id = organization_id;
  }  

  this.encode = () => {
    const date = new Date().getTime();
    
    this.payload.issuedAt = date;
    this.payload.expiresAt = date + expiration;

    return jwt.encode(this.payload, secret);
  };

  return this;  
};

Token.decode = (settings, token) => {
  const payload = jwt.decode(token, settings.secret);
  const now = new Date();
  
  // check token expiration first and don't care anymore if expired
  if (payload.expiresAt < now.getTime()) {
    throw new Error(ERR_EXPIRED);
  }

  const instance = Token(settings, payload.user_id, payload.organization_id);
  instance.payload = payload;
  return instance;
};

Token.ERR_EXPIRED = ERR_EXPIRED;

module.exports = Token;