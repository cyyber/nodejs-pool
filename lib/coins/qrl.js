"use strict";
const bignum = require('bignum');
const cnUtil = require('cryptoforknote-util');
const cnHashing = require('cryptonight-hashing');
const crypto = require('crypto');
const debug = require('debug')('coinFuncs');

let hexChars = new RegExp("[0-9a-f]+");

function Coin(data){
    this.bestExchange = global.config.payout.bestExchange;
    this.data = data;
    let instanceId = crypto.randomBytes(4);
    this.coinDevAddress = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";  // Developer Address
    this.poolDevAddress = "46BvkmZwu5bdPrfHguduUNe43MX9By6vsEAPASdkxjvWfXsoPcJbEXWi1LFm7Vroo2XLDThDzwtqRRehWSeSYhGoCLzg1tY";  // Venthos Address

    this.blockedAddresses = [
        this.coinDevAddress,
        this.poolDevAddress,
    ];

    this.exchangeAddresses = [
    ]; // These are addresses that MUST have a paymentID to perform logins with.

    this.prefix = 18;
    this.subPrefix = 42;
    this.intPrefix = 19;

    if (global.config.general.testnet === true) {
        this.prefix = 53;
        this.subPrefix = 63;
        this.intPrefix = 54;
    }

    this.supportsAutoExchange = false;

    this.niceHashDiff = 1000000;

    this.algoStr = function() {
        return "rx/0";
    }

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
        if(address.length !== 79) {
            return false;
        }
        let addr = address.substring(1);
        let addr_buff = new Buffer(addr, 'hex');

        const hash = crypto.createHash('sha256').update(addr_buff.slice(0, 35));

        return hash.digest('hex').slice(56) === addr_buff.slice(35).toString('hex')
    };

    this.convertBlob = function(blobBuffer){
        return blobBuffer;
    };

    this.constructNewBlob = function(blockTemplate, NonceBuffer){
        NonceBuffer.copy(blockTemplate, 39);
        return blockTemplate;
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
        this.seed_hash = template.seed_hash;
        this.nextBlob = function () {
            // Write a 32 bit integer, big-endian style to the 0 byte of the reserve offset.
            this.buffer.writeUInt32BE(++this.extraNonce, this.reserveOffset);
            // Convert the blob into something hashable.
            return this.buffer.toString('hex');
        };
        // Make it so you can get the raw block blob out.
        this.nextBlobWithChildNonce = function () {
            // Write a 32 bit integer, big-endian style to the 0 byte of the reserve offset.
            this.buffer.writeUInt32BE(++this.extraNonce, this.reserveOffset);
            // Don't convert the blob to something hashable.  You bad.
            return this.buffer.toString('hex');
        };
    };

    this.cryptoNight = function(convertedBlob, blockTemplate) {
        if (blockTemplate.height >= 942375) {
            return cnHashing.randomx(convertedBlob, Buffer.from(blockTemplate.seed_hash, 'hex'), 0);
        } else {
            return cnHashing.cryptonight(convertedBlob, 1, height);
        }
    };

}

module.exports = Coin;
