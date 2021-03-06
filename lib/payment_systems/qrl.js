"use strict";;
const async = require("async");
const debug = require("debug")("payments");

let hexChars = new RegExp("[0-9a-f]+");
let extraPaymentRound = false;
let paymentTimer = null;

let paymentQueue = async.queue(function (paymentDetails, callback) {
    /*
     support JSON URI: http://10.0.0.2:28082/json_rpc Args: {"id":"0","jsonrpc":"2.0","method":"transfer","params":{"destinations":[{"amount":68130252045355,"address":"A2MSrn49ziBPJBh8ZNEhhbfyLMou6mao4C1F5TLGUatmUnCxZArDYkcbAnVkVEopWVeak2rKDrmc8JpoS7n5dvfN9YDPBTG"}],"mixin":4,"payment_id":"7e52c5266de9fede7fb3abc0cd88f937b38b51426f7b34ff99729d28ce4e1142"}} +1ms
     payments Payment made: {"id":"0","jsonrpc":"2.0","result":{"fee":40199391255,"tx_hash":"c418708643f72635edf522490bfb2cae9d42a6dc1df30dcde844862dfd88f5b3","tx_key":""}} +2s
     */
    if (paymentTimer !== null){
        clearInterval(paymentTimer);
        paymentTimer = null;
    }

    // Protect our balance by making sure we have sufficient unlocked funds before trying to transact
    global.support.rpcWallet('getbalance', [], function (body) {
        if (body.result) {
            var amountToPay = paymentDetails.destinations.reduce(function (a, b) { return a + b; }, 0);
            if (body.result.unlocked_balance < amountToPay) {
                console.error("Wallet only has " + body.result.unlocked_balance + " unlocked balance, can't pay " + amountToPay + " worth of XMR. Retrying in " + timerRetry + " minutes!");
                if (!extraPaymentRound) {
                    setTimeout(function () {
                        makePayments();
                    }, global.config.payout.timerRetry * 60 * 1000);
                }
                extraPaymentRound = true;
                return callback(false);
            }
        } else {
            console.error("Issue checking pool wallet balance before making payments" + JSON.stringify(body.error));
            console.error("Will not make more payments until the payment daemon is restarted!");
            //toAddress, subject, body
            global.support.sendEmail(global.config.general.adminEmail, "Payment daemon unable to check wallet balance",
                "Hello,\r\nThe payment daemon has hit an issue checking the pool's wallet balance: " + JSON.stringify(body.error) +
                ".  Please investigate and restart the payment daemon as appropriate");
            return;
        }
    });

    debug("Making payment based on: " + JSON.stringify(paymentDetails));
    let priority = paymentDetails.priority;
    delete paymentDetails.priority;
    paymentDetails.fee = 0;
    paymentDetails.unlock_time = 0;

    let transferFunc = 'transfer';
    global.support.rpcWallet(transferFunc, paymentDetails, function (body) {
        paymentDetails.priority = priority;
        delete paymentDetails.fee;
        delete paymentDetails.unlock_time;
        debug("Payment made: " + JSON.stringify(body));
        if (body.hasOwnProperty('error')) {
            if (body.error.message === "not enough money"){
                console.error("Issue making payments, not enough money, will try later");
                if(!extraPaymentRound){
                    setTimeout(function(){
                        makePayments();
                    }, global.config.payout.timerRetry * 60 * 1000);
                }
                extraPaymentRound = true;
                return callback(false);
            } else {
                console.error("Issue making payments" + JSON.stringify(body.error));
                console.error("Will not make more payments until the payment daemon is restarted!");
                //toAddress, subject, body
                global.support.sendEmail(global.config.general.adminEmail, "Payment daemon unable to make payment",
                    "Hello,\r\nThe payment daemon has hit an issue making a payment: " + JSON.stringify(body.error) +
                    ".  Please investigate and restart the payment daemon as appropriate");
                return;
            }
        }
        if (paymentDetails.hasOwnProperty('payment_id')) {
            console.log("Payment made to " + paymentDetails.destinations[0].address + " with PaymentID: " + paymentDetails.payment_id + " For: " + global.support.coinToDecimal(paymentDetails.destinations[0].amount) + " QRL with a " + global.support.coinToDecimal(body.result.fee) + " QRL Mining Fee");
            return callback(body.result);
        } else {
            if (transferFunc === 'transfer') {
                console.log("Payment made out to multiple people, total fee: " + global.support.coinToDecimal(body.result.fee) + " QRL");
            }
            let intCount = 0;
            paymentDetails.destinations.forEach(function (details) {
                console.log("Payment made to: " + details.address + " For: " + global.support.coinToDecimal(details.amount) + " QRL");
                intCount += 1;
                if (intCount === paymentDetails.destinations.length) {
                    return callback(body.result);
                }
            });
        }
    });
}, 1);

paymentQueue.drain = function(){
    extraPaymentRound = false;
    startNormalPaymentTimer();
    global.database.setCache('lastPaymentCycle', Math.floor(Date.now()/1000));
};

function Payee(amount, address, paymentID, bitcoin) {
    this.amount = amount;
    this.address = address;
    this.paymentID = paymentID;
    this.bitcoin = bitcoin;
    this.blockID = 0;
    this.poolType = '';
    this.transactionID = 0;
    this.sqlID = 0;
    if (paymentID === null) {
        this.id = address;
    } else {
        this.id = address + "." + paymentID;
    }
    this.fee = 0;
    this.baseFee = global.support.decimalToCoin(global.config.payout.feeSlewAmount);
    this.setFeeAmount = function () {
        if (this.amount <= global.support.decimalToCoin(global.config.payout.walletMin)) {
            this.fee = this.baseFee;
        } else if (this.amount <= global.support.decimalToCoin(global.config.payout.feeSlewEnd)) {
            let feeValue = this.baseFee / (global.support.decimalToCoin(global.config.payout.feeSlewEnd) - global.support.decimalToCoin(global.config.payout.walletMin));
            this.fee = this.baseFee - ((this.amount - global.support.decimalToCoin(global.config.payout.walletMin)) * feeValue);
        }
        this.fee = Math.floor(this.fee);
    };

    this.makePaymentWithID = function () {
        let paymentDetails = {
            destinations: [
                {
                    amount: this.amount - this.fee,
                    address: this.address
                }
            ],
            mixin: global.config.payout.mixIn,
            payment_id: this.paymentID
        };
        let identifier = this.id;
        let amount = this.amount;
        let address = this.address;
        let paymentID = this.paymentID;
        let payee = this;
        debug("Payment Details: " + JSON.stringify(paymentDetails));
        paymentQueue.push(paymentDetails, function (body) {
            if (body.fee && body.fee > 10) {
                debug("Successful payment sent to: " + identifier);
                global.mysql.query("INSERT INTO transactions (bitcoin, address, payment_id, xmr_amt, transaction_hash, mixin, fees, payees) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    [0, address, paymentID, amount, body.tx_hash.match(hexChars)[0], global.config.payout.mixIn, body.fee, 1]).then(function (result) {
                    payee.transactionID = result.insertId;
                    payee.trackPayment();
                });
                if (global.config.general.discordPayoutAnnounce === true) {
                    global.support.poolBotMsg("Pool paid out: " + global.support.coinToDecimal(amount)  + " QRL to 1 miner");
                }
            } else {
                console.error("Unknown error from the wallet.");
            }
        });
    };

    this.makePaymentAsIntegrated = function () {
        let paymentDetails = {
            destinations: [
                {
                    amount: this.amount - this.fee,
                    address: this.address
                }
            ],
            mixin: global.config.payout.mixIn
        };
        let identifier = this.id;
        let amount = this.amount;
        let address = this.address;
        let payee = this;

        debug("Payment Details: " + JSON.stringify(paymentDetails));
        paymentQueue.push(paymentDetails, function (body) {
            if (body.fee && body.fee > 10) {
                debug("Successful payment sent to: " + identifier);
                global.mysql.query("INSERT INTO transactions (bitcoin, address, xmr_amt, transaction_hash, mixin, fees, payees) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [0, address, amount, body.tx_hash.match(hexChars)[0], global.config.payout.mixIn, body.fee, 1]).then(function (result) {
                    payee.transactionID = result.insertId;
                    payee.trackPayment();
                });
                if (global.config.general.discordPayoutAnnounce === true) {
                    global.support.poolBotMsg("Pool paid out: " + global.support.coinToDecimal(amount)  + " QRL to 1 miner");
                }
            } else {
                console.error("Unknown error from the wallet.");
            }
        });
    };

    this.trackPayment = function () {
        global.mysql.query("UPDATE balance SET amount = amount - ? WHERE id = ?", [this.amount, this.sqlID]);
        global.mysql.query("INSERT INTO payments (unlocked_time, paid_time, pool_type, payment_address, transaction_id, bitcoin, amount, payment_id, transfer_fee)" +
            " VALUES (now(), now(), ?, ?, ?, ?, ?, ?, ?)", [this.poolType, this.address, this.transactionID, this.bitcoin, this.amount - this.fee, this.paymentID, this.fee]);
    };
}

function makePayments() {
    let pool_types = ['fees', 'pplns', 'pps', 'solo'];
    pool_types.forEach(function (pool_type) {
        makePaymentsForPoolType(pool_type);
    });
}

function makePaymentsForPoolType(pool_type) {
    global.mysql.query("SELECT * FROM balance WHERE pool_type = ? AND amount >= ?", [pool_type, global.support.decimalToCoin(global.config.payout.walletMin)]).then(function (rows) {
        console.log("Loaded all [" + pool_type + "] payees into the system for processing");
        let paymentDestinations = [];
        let totalAmount = 0;
        let roundCount = 0;
        let payeeList = [];
        let payeeObjects = {};
        rows.forEach(function (row) {
            debug("Starting round for: " + JSON.stringify(row));
            let payee = new Payee(row.amount, row.payment_address, row.payment_id, row.bitcoin);
            payeeObjects[row.payment_address] = payee;
            global.mysql.query("SELECT payout_threshold FROM users WHERE username = ?", [payee.id]).then(function (userRow) {
                roundCount += 1;
                let threshold = 0;
                if (userRow.length !== 0) {
                    threshold = userRow[0].payout_threshold;
                }
                payee.poolType = row.pool_type;
                payee.sqlID = row.id;
                if (payee.poolType === "fees" && payee.address === global.config.payout.feeAddress && payee.amount >= ((global.support.decimalToCoin(global.config.payout.feesForTXN) + global.support.decimalToCoin(global.config.payout.exchangeMin)))) {
                    debug("This is the fee address internal check for value");
                    payee.amount -= global.support.decimalToCoin(global.config.payout.feesForTXN);
                } else if (payee.address === global.config.payout.feeAddress && payee.poolType === "fees") {
                    debug("Unable to pay fee address.");
                    payee.amount = 0;
                }
                let remainder = payee.amount % (global.config.payout.denom * global.config.general.sigDivisor);
                if (remainder !== 0) {
                    payee.amount -= remainder;
                }
                if (payee.amount > threshold) {
                    payee.setFeeAmount();
                    if (payee.bitcoin === 0 && payee.paymentID === null && payee.amount !== 0 && payee.amount > 0 && global.coinFuncs.isIntegratedAddress(payee.address) === false) {
                        debug("Adding " + payee.id + " to the list of people to pay (OG Address).  Payee balance: " + global.support.coinToDecimal(payee.amount));
                        paymentDestinations.push({amount: payee.amount - payee.fee, address: payee.address});
                        totalAmount += payee.amount;
                        payeeList.push(payee);
                    } else if (payee.bitcoin === 0 && payee.paymentID === null && payee.amount !== 0 && payee.amount > 0 && global.coinFuncs.isIntegratedAddress(payee.address) === true && (payee.amount >= global.support.decimalToCoin(global.config.payout.exchangeMin) || (payee.amount > threshold && threshold !== 0))) {
                        // Special code to handle integrated payment addresses.  What a pain in the rear.
                        // These are exchange addresses though, so they need to hit the exchange payout amount.
                        debug("Adding " + payee.id + " to the list of people to pay (Integrated Address).  Payee balance: " + global.support.coinToDecimal(payee.amount));
                        payee.makePaymentAsIntegrated();
                    } else if ((payee.amount >= global.support.decimalToCoin(global.config.payout.exchangeMin) || (payee.amount > threshold && threshold !== 0)) && payee.bitcoin === 0) {
                        debug("Adding " + payee.id + " to the list of people to pay (Payment ID Address).  Payee balance: " + global.support.coinToDecimal(payee.amount));
                        payee.makePaymentWithID();
                    } else if ((payee.amount >= global.support.decimalToCoin(global.config.payout.exchangeMin) || (payee.amount > threshold && threshold !== 0)) && payee.bitcoin === 1) {
                        debug("Adding " + payee.id + " to the list of people to pay (Bitcoin Payout).  Payee balance: " + global.support.coinToDecimal(payee.amount));
                        payee.makeBitcoinPayment();
                    }
                }
                debug("Went: " + roundCount + " With: " + paymentDestinations.length + " Possible destinations and: " + rows.length + " Rows");
                if (roundCount === rows.length && paymentDestinations.length > 0) {
                    while (paymentDestinations.length > 0) {
                        let paymentDetails = {
                            destinations: paymentDestinations.splice(0, global.config.payout.maxPaymentTxns),
                            mixin: global.config.payout.mixIn
                        };
                        console.log("Paying out: " + paymentDetails.destinations.length + " people");
                        paymentQueue.push(paymentDetails, function (body) {  //jshint ignore:line
                            // This is the only section that could potentially contain multiple txns.  Lets do this safely eh?
                            if (body.fee && body.fee > 10) {
                                debug("Made it to the SQL insert for transactions");
                                let totalAmount = 0;
                                paymentDetails.destinations.forEach(function (payeeItem) {
                                    totalAmount += payeeObjects[payeeItem.address].amount;
                                    totalAmount += payeeObjects[payeeItem.address].fee;
                                });
                                global.mysql.query("INSERT INTO transactions (bitcoin, address, payment_id, xmr_amt, transaction_hash, mixin, fees, payees) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                    [0, null, null, totalAmount, body.tx_hash.match(hexChars)[0], global.config.payout.mixIn, body.fee, paymentDetails.destinations.length]).then(function (result) {
                                    paymentDetails.destinations.forEach(function (payeeItem) {
                                        payee = payeeObjects[payeeItem.address];
                                        payee.transactionID = result.insertId;
                                        payee.trackPayment();
                                    });
                                });
                                if (global.config.general.discordPayoutAnnounce === true) {
                                    global.support.poolBotMsg("Pool paid out: " + global.support.coinToDecimal(totalAmount)  + " QRL to " + paymentDetails.destinations.length + " miners");
                                }
                            } else {
                                console.error("Unknown error from the wallet.");
                            }
                        });
                    }
                }
            });
        });
    });
}

function startNormalPaymentTimer() {
    if (global.config.payout.timer > 35791) {
        console.error("Payout timer is too high.  Please use a value under 35791 to avoid overflows.");
    } else {
        console.log("Setting the payment timer to: " + global.config.payout.timer + " minutes for its next normal run.");
        paymentTimer = setInterval(makePayments, global.config.payout.timer * 60 * 1000);
    }
}

function init() {
    global.support.rpcWallet("store", [], function () {
    });
    setInterval(function () {
        global.support.rpcWallet("store", [], function () {
        });
    }, 60000);
    console.log("(Payout Timer Configuration) Normal Timer: " + global.config.payout.timer + " minutes, Out of Money Retry Timer: " + global.config.payout.timerRetry + " minutes");
    startNormalPaymentTimer();
    makePayments();
}

init();
