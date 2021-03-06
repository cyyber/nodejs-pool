"use strict";
const CircularBuffer = require('circular-buffer');
const request = require('request');
const requestJson = require('request-json');
const moment = require('moment');
const debug = require('debug')('support');
const fs = require('fs');
const nodemailer = require('nodemailer');

function circularBuffer(size) {
    let buffer = CircularBuffer(size);

    buffer.sum = function () {
        if (this.size() === 0) {
            return 1;
        }
        return this.toarray().reduce(function (a, b) {
            return a + b;
        });
    };

    buffer.average = function (lastShareTime) {
        if (this.size() === 0) {
            return global.config.pool.targetTime * 1.5;
        }
        let extra_entry = (Date.now() / 1000) - lastShareTime;
        return (this.sum() + Math.round(extra_entry)) / (this.size() + 1);
    };

    buffer.clear = function () {
        let i = this.size();
        while (i > 0) {
            this.deq();
            i = this.size();
        }
    };

    return buffer;
}

function sendEmail(toAddress, subject, body){
    let transport = nodemailer.createTransport({
        host: 'mail.your-pool.local',
        port: 587,
        secure: false,
        auth: {
            user: "support@your-pool.local",
            pass: "YOUR_PASSWORD",
        },
        tls: {
            rejectUnauthorized: false
        },
    });

    const message = {
        from: 'support@your-pool.com',
        to: toAddress,
        bcc: 'support@your-pool.com,',
        subject: subject,
        text: body
    };

   transport.sendMail(message, function(err, info) {
       if (err) {
         console.error("Did not send e-mail successfully!  Response: " + JSON.stringify(err))
       } else {
         console.log("Email sent successfully!  Response: " + JSON.stringify(info))
       }
    });
}

function poolBotMsg(message){
    if (global.config.general.discordWebhook.length === 0) {
        return;
    }
    let uri = "https://discordapp.com/";
    let path = "api/webhooks/" + global.config.general.discordWebhook;
    let client = requestJson.createClient(uri, {timeout: 300000});
    client.headers["Content-Type"] = "application/json";
    client.headers["Accept"] = "application/json";
    client.post(path, { content: message }, function (err, res, body) {
        if (err) {
            console.error("Pool Bot failed to message Discord, Response: " + message + " Response: " + JSON.stringify(body));
        }
        debug("JSON result: " + JSON.stringify(body));
        console.log("Pool Bot messaged Discord: " + message);
    });
}

function jsonRequest(host, port, data, callback, path) {
    path = path || 'json_rpc';
    let uri;
    if (global.config.rpc.https) {
        uri = "https://" + host + ":" + port + "/";
    } else {
        uri = "http://" + host + ":" + port + "/";
    }
    debug("JSON URI: " + uri + path + " Args: " + JSON.stringify(data));
    let client = requestJson.createClient(uri, {timeout: 300000});
    client.headers["Content-Type"] = "application/json";
    client.headers["Content-Length"] = data.length;
    client.headers["Accept"] = "application/json";
    if (global.config.payout.rpcPasswordEnabled && host === global.config.wallet.address && port === global.config.wallet.port){
        fs.readFile(global.config.payout.rpcPasswordPath, 'utf8', function(err, data){
            if (err){
                console.error("RPC password enabled, unable to read the file due to: " + JSON.stringify(err));
                return;
            }
            let passData = data.split(":");
            client.setBasicAuth(passData[0], passData[1]);
            request.post(uri, {
                auth:{
                    user: passData[0],
                    pass: passData[1],
                    sendImmediately: false
                },
                data: JSON.stringify(data)
            }, function (err, res, body) {
                if (err) {
                    return callback(err);
                }
                debug("JSON result: " + JSON.stringify(body));
                return callback(body);
            });
        });
    } else {
        client.post(path, data, function (err, res, body) {
            if (err) {
                return callback(err);
            }
            debug("JSON result: " + JSON.stringify(body));
            return callback(body);
        });
    }
}

function rpc(host, port, method, params, callback) {

    let data = {
        id: "0",
        jsonrpc: "2.0",
        method: method,
        params: params
    };
    return jsonRequest(host, port, data, callback);
}
function formatDate(date) {
    // Date formatting for MySQL date time fields.
    return moment(date).format('YYYY-MM-DD HH:mm:ss');
}

function formatDateFromSQL(date) {
    // Date formatting for MySQL date time fields.
    let ts = new Date(date);
    return Math.floor(ts.getTime() / 1000);
}

function coinToDecimal(amount) {
    return amount / global.config.coin.sigDigits;
}

function decimalToCoin(amount) {
    return Math.round(amount * global.config.coin.sigDigits);
}

function bitcoinDecimalToCoin(amount) {
    return Math.round(amount * 100000000);
}

function bitcoinCoinToDecimal(amount) {
    return amount / 100000000;
}

function blockCompare(a, b) {
    if (a.height < b.height) {
        return 1;
    }

    if (a.height > b.height) {
        return -1;
    }
    return 0;
}

function tsCompare(a, b) {
    if (a.ts < b.ts) {
        return 1;
    }

    if (a.ts > b.ts) {
        return -1;
    }
    return 0;
}

module.exports = function () {
    return {
        rpcDaemon: function (method, params, callback) {
            rpc(global.config.daemon.address, global.config.daemon.port, method, params, callback);
        },
        rpcWallet: function (method, params, callback) {
            rpc(global.config.wallet.address, global.config.wallet.port, method, params, callback);
        },
        jsonRequest: jsonRequest,
        circularBuffer: circularBuffer,
        formatDate: formatDate,
        coinToDecimal: coinToDecimal,
        decimalToCoin: decimalToCoin,
        bitcoinDecimalToCoin: bitcoinDecimalToCoin,
        bitcoinCoinToDecimal: bitcoinCoinToDecimal,
        formatDateFromSQL: formatDateFromSQL,
        blockCompare: blockCompare,
        sendEmail: sendEmail,
        tsCompare: tsCompare,
        poolBotMsg: poolBotMsg
    };
};
