var keys = require('../../../env/development');

var mandrill = require('mandrill-api/mandrill');
var swig = require('swig');
var Promise = require('bluebird');
var fs = Promise.promisifyAll(require('fs'));

var mandrillClient = new mandrill.Mandrill(keys.MANDRILL.api);


var template = {
  from: "MSF Dashboard",
  email: "noreply@msfTemp.com",
  subj: "The sensor detected a break in the cold chain"
};

var sendEmail = function sendEmail(alert, subject, message_html) {
    console.log('alert is ', alert)
  var message = {
      "html": message_html,
      "subject": subject,
      "from_email": template.email,
      "from_name": template.from,
      "to": [{
              "email": alert.email
          }],
      "important": false,
      "track_opens": true,
      "auto_html": false,
      "preserve_recipients": true,
      "merge": false
  };
  var async = false;
  var ip_pool = "Main Pool";
  mandrillClient.messages.send({"message": message, "async": async, "ip_pool": ip_pool}, function() {
      console.log('email sent!!!');
  }, function(e) {
      console.log('A mandrill error occurred: ' + e.name + ' - ' + e.message);
  });
};

function renderTemp(templateFilename, alert) {
    templateFilename = __dirname + templateFilename;
    fs.readFile(templateFilename, function (err, contents) {
        if(err) throw new Error(err);
        contents = contents.toString();
        var renderedTemp = swig.render(contents, {locals: {alert: alert}});
        var subject = template.subj;
        // sendEmail(alert, subject, renderedTemp);
  });
}

var confirmEmail = function (alert) {
    var templateFile = "/confirmTemp.html";
    renderTemp(templateFile, alert);
};

module.exports = {
    confirmEmail: confirmEmail
};
