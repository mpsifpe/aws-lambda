'use strict';

const addrs = require("email-addresses");

module.exports.handle = async (event, context, callback) => {
  try {
    console.log('Spam filter');

    var sesNotification = event.Records[0].ses;
    console.log("SES Notification:\n", JSON.stringify(sesNotification, null, 2));

    if (sesNotification.receipt.spfVerdict.status === 'FAIL'
      || sesNotification.receipt.dkimVerdict.status === 'FAIL'
      || sesNotification.receipt.spamVerdict.status === 'FAIL'
      || sesNotification.receipt.virusVerdict.status === 'FAIL') {

      console.log('Dropping spam');
      // Stop processing rule set, dropping message
      callback(null, {'disposition':'STOP_RULE_SET'});
    }
    console.log('domain:\n', JSON.stringify(sesNotification.mail.commonHeaders.from[0], null, 2));

    const address = addrs.parseOneAddress(sesNotification.mail.commonHeaders.from[0]);
    if(address.domain === process.env.DOMAIN){
      console.log('Domain is CSU.');
      callback(null, {'disposition':'CONTINUE'});
    } else {
      console.log('Domain is not CSU.');
      callback(null, {'disposition':'STOP_RULE_SET'});
    }
  } catch (error) {
    return error;
  }
};
