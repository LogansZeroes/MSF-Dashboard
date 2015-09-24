var keys = require('../../../env/development');

var mandrill = require('mandrill-api/mandrill');
var swig = require('swig');
var Promise = require('bluebird');
var fs = Promise.promisifyAll(require('fs'));

var mandrillClient = new mandrill.Mandrill(keys.MANDRILL.api);

//confirmation emails

var extreme = {
  tag: "Exxxtreme",
  from: "Exxxtreme",
  email: "exxxxxxxtreme@gmail.com",
  confirmSubj: "Your order has been confirmed",
  updateSubj: "Your order status has been updated"
};

var sendEmail = function sendEmail(order, subject, message_html) {
  var message = {
      "html": message_html,
      "subject": subject,
      "from_email": extreme.email,
      "from_name": extreme.from,
      "to": [{
              "email": order.email,
              "name": order.name
          }],
      "important": false,
      "track_opens": true,
      "auto_html": false,
      "preserve_recipients": true,
      "merge": false,
      "tags": [
          extreme.tag
      ]
  };
  var async = false;
  var ip_pool = "Main Pool";
  mandrillClient.messages.send({"message": message, "async": async, "ip_pool": ip_pool}, function() {
      console.log('email sent!!!');
  }, function(e) {
      console.log('A mandrill error occurred: ' + e.name + ' - ' + e.message);
  });
};

function renderTemp(templateFilename, order) {
  templateFilename = __dirname + templateFilename;
  fs.readFile(templateFilename, function (err, contents) {
      if(err) throw new Error(err);
    contents = contents.toString();
    var renderedTemp = swig.render(contents, {locals: {order: order}});
    var subject = order.status === "confirmed" ? extreme.confirmSubj : extreme.updateSubj;
    sendEmail(order, subject, renderedTemp);
  });
}

var confirmEmail = function (order) {
  var templateFile = order.status === "confirmed" ? "/confirmTemp.html" : "/updateTemp.html";
  renderTemp(templateFile, order);
};

module.exports = {
  confirmEmail: confirmEmail
};
