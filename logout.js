const ERR_UNKNOWN = "UNKNOWN ERROR";

module.exports = (r, settings) => {
  
  return (req, res) => {
    r.table('tokens')
     .get(req.auth.id)
     .delete()
     .then(() => {
      res.send({ success: true, message: 'Logged out!' });
     })
     .catch((error) => {
       res.status(500).send(ERR_UNKNOWN);
     });
  };

};
