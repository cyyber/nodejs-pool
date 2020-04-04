"use strict";
const bignum = require('bignum');
const cnUtil = require('intensecoin-util');
const cnHashing = require('cryptonight-hashing');
const crypto = require('crypto');
const debug = require('debug')('coinFuncs');

let hexChars = new RegExp("[0-9a-f]+");

function Coin(data){
    this.bestExchange = global.config.payout.bestExchange;
    this.data = data;
    let instanceId = crypto.randomBytes(4);
    this.coinDevAddress = "iz5w5LGYQY2SseEd9BTaF8SRqFmZLTEVDBEGidvzYnZBcc9RMEHXs2rXBZfAvXQPPc85NR2JeZcQUj7jjBcgw26b1Rk6m4H2z";  // Developer Address
    this.poolDevAddress = "iz5imhe9C7vWnjZtZBFtT8MwNxVuJuryUUHXSAtnWUo93CJzNdZBizHQExPRCHUBi36tk2BcigPAFRDA4cnddGXF1R6j69n3w";  // Venthos Address

    this.blockedAddresses = [
        this.coinDevAddress,
        this.poolDevAddress
    ];

    this.exchangeAddresses = [
        "iz4pcDLxmo7KqbFmYjE5aGDv68U9Sgm1ePFjWUY24vzyPeGMcoG894MAFjrtHbaMv1TygTcvJWzGN3zNR6PeEYuc1w8V2tiMW" // stocks.exchange
    ]; // These are addresses that MUST have a paymentID to perform logins with.

    this.prefix = 251;
    this.intPrefix = 129;

    if (global.config.general.testnet === true) {
        this.prefix = 25247;
        this.intPrefix = 3745;
    }

    this.supportsAutoExchange = false;

    this.niceHashDiff = 400000;

    this.getBlockHeaderByHash = function(blockHash, callback){
        global.support.rpcDaemon('getblockheaderbyhash', {"hash": blockHash}, function (body) {
            if (typeof(body) !== 'undefined' && body.hasOwnProperty('result')){
                return callback(null, body.result.block_header);
            } else {
                console.error(JSON.stringify(body));
                return callback(true, body);
            }
        });
    };

    this.getBlockHeaderByHeight = function(blockHeight, callback){
        global.support.rpcDaemon('getblockheaderbyheight', {"height": blockHeight}, function (body) {
            if (typeof(body) !== 'undefined' && body.hasOwnProperty('result')){
                return callback(null, body.result.block_header);
            } else {
                console.error(JSON.stringify(body));
                return callback(true, body);
            }
        });
    };

    this.getLastBlockHeader = function(callback){
        global.support.rpcDaemon('getlastblockheader', [], function (body) {
            if (typeof(body) !== 'undefined' && body.hasOwnProperty('result')){
                return callback(null, body.result.block_header);
            } else {
                console.error(JSON.stringify(body));
                return callback(true, body);
            }
        });
    };

    this.getBlockTemplate = function(walletAddress, callback){
        global.support.rpcDaemon('getblocktemplate', {
            reserve_size: 17,
            wallet_address: walletAddress
        }, function(body){
            return callback(body);
        });
    };

    this.submitBlock = function(blockBlobData, callback){
        global.support.rpcDaemon('submitblock', [blockBlobData], function(body){
            if (typeof(body) !== 'undefined' && body.hasOwnProperty('result')){
                return callback(null, body.result.status);
            } else {
                console.error(JSON.stringify(body));
                return callback(true, body);
            }
        });
    };

    this.getBalance = function(callback){
        global.support.rpcWallet('getbalance', [], function (body) {
            if (typeof(body) !== 'undefined' && body.hasOwnProperty('result')){
                return callback(null, body.result);
            } else {
                console.error(JSON.stringify(body));
                return callback(true, body);
            }
        });
    };

    this.getHeight = function(callback){
        global.support.rpcWallet('getheight', [], function (body) {
            if (typeof(body) !== 'undefined' && body.hasOwnProperty('result')){
                return callback(null, body.result.height);
            } else {
                console.error(JSON.stringify(body));
                return callback(true, body);
            }
        });
    };

    this.baseDiff = function(){
        return bignum('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16);
    };

    this.validateAddress = function(address){
        // This function should be able to be called from the async library, as we need to BLOCK ever so slightly to verify the address.
        address = new Buffer(address);
        if (cnUtil.address_decode(address) === this.prefix){
            return true;
        }
        return cnUtil.address_decode_integrated(address) === this.intPrefix;
    };

    this.isIntegratedAddress = function(address) {
        address = new Buffer(address);
        return cnUtil.address_decode_integrated(address) === this.intPrefix;
    };

    this.convertBlob = function(blobBuffer){
        return cnUtil.convert_blob(blobBuffer);
    };

    this.constructNewBlob = function(blockTemplate, NonceBuffer){
        return cnUtil.construct_block_blob(blockTemplate, NonceBuffer);
    };

    this.getBlockID = function(blockBuffer){
        return cnUtil.get_block_id(blockBuffer);
    };

    this.BlockTemplate = function(template) {
        /*
        Generating a block template is a simple thing.  Ask for a boatload of information, and go from there.
        Important things to consider.
        The reserved space is 13 bytes long now in the following format:
        Assuming that the extraNonce starts at byte 130:
        |130-133|134-137|138-141|142-145|
        |minerNonce/extraNonce - 4 bytes|instanceId - 4 bytes|clientPoolNonce - 4 bytes|clientNonce - 4 bytes|
        This is designed to allow a single block template to be used on up to 4 billion poolSlaves (clientPoolNonce)
        Each with 4 billion clients. (clientNonce)
        While being unique to this particular pool thread (instanceId)
        With up to 4 billion clients (minerNonce/extraNonce)
        Overkill?  Sure.  But that's what we do here.  Overkill.
         */

        // Set this.blob equal to the BT blob that we get from upstream.
        this.blob = template.blocktemplate_blob;
        this.idHash = crypto.createHash('md5').update(template.blocktemplate_blob).digest('hex');
        // Set this.diff equal to the known diff for this block.
        this.difficulty = template.difficulty;
        // Set this.height equal to the known height for this block.
        this.height = template.height;
        // Set this.reserveOffset to the byte location of the reserved offset.
        this.reserveOffset = template.reserved_offset;
        // Set this.buffer to the binary decoded version of the BT blob.
        this.buffer = new Buffer(this.blob, 'hex');
        // Copy the Instance ID to the reserve offset + 4 bytes deeper.  Copy in 4 bytes.
        instanceId.copy(this.buffer, this.reserveOffset + 4, 0, 3);
        // Generate a clean, shiny new buffer.
        this.previous_hash = new Buffer(32);
        // Copy in bytes 7 through 39 to this.previous_hash from the current BT.
        this.buffer.copy(this.previous_hash, 0, 7, 39);
        // Reset the Nonce. - This is the per-miner/pool nonce
        this.extraNonce = 0;
        // The clientNonceLocation is the location at which the client pools should set the nonces for each of their clients.
        this.clientNonceLocation = this.reserveOffset + 12;
        // The clientPoolLocation is for multi-thread/multi-server pools to handle the nonce for each of their tiers.
        this.clientPoolLocation = this.reserveOffset + 8;
        this.nextBlob = function () {
            // Write a 32 bit integer, big-endian style to the 0 byte of the reserve offset.
            this.buffer.writeUInt32BE(++this.extraNonce, this.reserveOffset);
            // Convert the blob into something hashable.
            return global.coinFuncs.convertBlob(this.buffer).toString('hex');
        };
        // Make it so you can get the raw block blob out.
        this.nextBlobWithChildNonce = function () {
            // Write a 32 bit integer, big-endian style to the 0 byte of the reserve offset.
            this.buffer.writeUInt32BE(++this.extraNonce, this.reserveOffset);
            // Don't convert the blob to something hashable.  You bad.
            return this.buffer.toString('hex');
        };
    };

    this.cryptoNight = function(convertedBlob, height) {
        let blockVersion = convertedBlob[0];
        let cn_variant = this.variant(blockVersion);

        return cnHashing.cryptonight(convertedBlob, cn_variant, height);
    };

    this.oldAlgorithmCheck = function(convertedBlob, badHash, height) {
        let blockVersion = convertedBlob[0] - 1; // Start with the previous blockchain version
        let lastVariant = null;

        for (let i = blockVersion; i >= 1; i--) {
            let cn_variant = this.variant(i);
            if (lastVariant === null || cn_variant < lastVariant) {
                let hash = cnHashing.cryptonight(convertedBlob, cn_variant, height);
                if (hash.toString('hex') == badHash) {
                    return this.variantName(i);
                }
            }
            lastVariant = cn_variant;
        }
        return null;
    };

    this.variant = function(blockVersion) {
        switch (blockVersion) {
            case 4:
                return 1;
                break;
            case 5:
                return 2;
                break;
            case 6:
                return 4;
                break;
            default:
                return 0;
        }
    };

    this.variantName = function(blockVersion) {
        switch (blockVersion) {
            case 4:
                return "CryptoNight v1";
                break;
            case 5:
                return "CryptoNight v2";
                break;
            case 6:
                return "CryptoNightR (v4)";
                break;
            default:
                return "CryptoNight (v0)";
        }
    };

    this.variantShortName = function(blockHeight) {
        if (global.config.general.testnet === true) {
            if (blockHeight >= 801) {
                return "cn/r";
            } else if (blockHeight >= 310) {
                return "cn/2";
            } else if (blockHeight >= 301) {
                return "cn/1";
            } else {
                return "cn/0";
            }
        } else {
            if (blockHeight >= 391500) {
                return "cn/r";
            } else if (blockHeight >= 296287) {
                return "cn/2";
            } else if (blockHeight >= 166134) {
                return "cn/1";
            } else {
                return "cn/0";
            }
        }
    };

}

module.exports = Coin;