module.exports = (params, list) => {
  const valid = [];
  list.forEach((param) => {    
    if (params[param]) {
      valid.push(param);
    }
  });  
  return valid.length == list.length;  
};