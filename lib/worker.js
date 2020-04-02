"use strict";
const debug = require("debug")("worker");
const async = require("async");
const sprintf = require("sprintf-js").sprintf;

let threadName = "Worker Server ";
let cycleCount = 0;
let lastBlockHash = null;

function updateShareStats() {
    // This is an omni-worker to deal with all things share-stats related
    // Time based averages are worked out on ring buffers.
    // Buffer lengths?  You guessed it, configured in SQL.
    // Stats timeouts are 30 seconds, so everything for buffers should be there.
    let currentTime = Date.now();
    let activeAddresses = [];
    async.waterfall([
        function (callback) {
            global.coinFuncs.getLastBlockHeader(function (err, body) {
                if (err !== null){
                    return callback(err, "Invalid block header");
                }
                callback(null, body.height + 1, body.difficulty);
            });
        },
        function (height, difficulty, callback) {
            let locTime = Date.now() - 600000;
            let identifierTime = Date.now() - 1800000;
            let localStats = {pplns: 0, pps: 0, solo: 0, prop: 0, global: 0, miners: {}, minersPplns: {}};
            let localMinerCount = {pplns: 0, pps: 0, solo: 0, prop: 0, global: 0};
            let localTimes = {
                pplns: locTime, pps: locTime, solo: locTime, prop: locTime,
                global: locTime, miners: {}
            };
            let minerList = [];
            let identifiers = {};
            let loopBreakout = 0;
            let totalPplnsShares = 0;
            let pplnsDepth = difficulty * global.config.pplns.shareMulti;
            async.doUntil(function (callback_until) {
                let oldestTime = Date.now();
                let loopCount = 0;
                let txn = global.database.env.beginTxn({readOnly: true});
                let cursor = new global.database.lmdb.Cursor(txn, global.database.shareDB);
                for (let found = (cursor.goToRange(height) === height); found; found = cursor.goToNextDup()) {
                    cursor.getCurrentBinary(function (key, share) {  // jshint ignore:line
                        try {
                            share = global.protos.Share.decode(share);
                        } catch (e) {
                            console.error(share);
                            return;
                        }
                        let minerID = share.paymentAddress;
                        if (typeof(share.paymentID) !== 'undefined' && share.paymentID.length > 10) {
                            minerID = minerID + '.' + share.paymentID;
                        }
                        // Store PPLNS share count per-miner
                        if (totalPplnsShares < pplnsDepth) {
                            if (minerID in localStats.minersPplns) {
                                localStats.minersPplns[minerID] += share.shares;
                            } else {
                                localStats.minersPplns[minerID] = share.shares;
                            }
                            totalPplnsShares += share.shares;
                        }
                        if (share.timestamp < oldestTime) {
                            oldestTime = share.timestamp;
                        }
                        if (share.timestamp <= identifierTime) {
                            return;
                        }
                        if (minerID in identifiers && identifiers[minerID].indexOf(share.identifier) >= 0) {
                            loopCount += 1;
                        } else if (minerID in identifiers) {
                            identifiers[minerID].push(share.identifier);
                        } else {
                            identifiers[minerID] = [share.identifier];
                        }
                        if (share.timestamp <= locTime) {
                            return;
                        }
                        let minerIDWithIdentifier = minerID + "_" + share.identifier;
                        localStats.global += share.shares;
                        if (localTimes.global <= share.timestamp) {
                            localTimes.global = share.timestamp;
                        }
                        let minerType;
                        switch (share.poolType) {
                            case global.protos.POOLTYPE.PPLNS:
                                minerType = 'pplns';
                                localStats.pplns += share.shares;
                                if (localTimes.pplns <= share.timestamp) {
                                    localTimes.pplns = share.timestamp;
                                }
                                break;
                            case global.protos.POOLTYPE.PPS:
                                localStats.pps += share.shares;
                                minerType = 'pps';
                                if (localTimes.pps <= share.timestamp) {
                                    localTimes.pps = share.timestamp;
                                }
                                break;
                            case global.protos.POOLTYPE.SOLO:
                                localStats.solo += share.shares;
                                minerType = 'solo';
                                if (localTimes.solo <= share.timestamp) {
                                    localTimes.solo = share.timestamp;
                                }
                                break;
                        }
                        if (minerList.indexOf(minerID) >= 0) {
                            localStats.miners[minerID] += share.shares;
                            if (localTimes.miners[minerID] < share.timestamp) {
                                localTimes.miners[minerID] = share.timestamp;
                            }
                        } else {
                            localMinerCount[minerType] += 1;
                            localMinerCount.global += 1;
                            localStats.miners[minerID] = share.shares;
                            localTimes.miners[minerID] = share.timestamp;
                            minerList.push(minerID);
                        }
                        if (minerList.indexOf(minerIDWithIdentifier) >= 0) {
                            localStats.miners[minerIDWithIdentifier] += share.shares;
                            if (localTimes.miners[minerIDWithIdentifier] < share.timestamp) {
                                localTimes.miners[minerIDWithIdentifier] = share.timestamp;
                            }
                        } else {
                            localStats.miners[minerIDWithIdentifier] = share.shares;
                            localTimes.miners[minerIDWithIdentifier] = share.timestamp;
                            minerList.push(minerIDWithIdentifier);
                        }
                    });
                }
                cursor.close();
                txn.abort();
                return callback_until(null, oldestTime);
            }, function (oldestTime) {
                height -= 1;
                loopBreakout += 1;
                // TODO: Handle this better than setting a max of 1024 blocks, but still making sure we get diff * multiShare worth of shares
                if (loopBreakout > 1024 || height < 0) {
                    return true;
                }
                return totalPplnsShares >= pplnsDepth;
            }, function (err) {
                // todo: Need to finish parsing the cached data into caches for caching purproses.
                let globalMinerList = global.database.getCache('minerList');
                if (globalMinerList === false) {
                    globalMinerList = [];
                }
                let cache_updates = {};
                // pplns: 0, pps: 0, solo: 0, prop: 0, global: 0
                ['pplns', 'pps', 'solo', 'prop', 'global'].forEach(function (key) {
                    let cachedData = global.database.getCache(key + "_stats");
                    if (cachedData !== false) {
                        cachedData.hash = Math.floor(localStats[key] / 600);
                        cachedData.lastHash = localTimes[key];
                        cachedData.minerCount = localMinerCount[key];
                        if (!cachedData.hasOwnProperty("hashHistory")) {
                            cachedData.hashHistory = [];
                            cachedData.minerHistory = [];
                        }
                        if (cycleCount === 0) {
                            cachedData.hashHistory.unshift({ts: currentTime, hs: cachedData.hash});
                            if (cachedData.hashHistory.length > global.config.general.statsBufferLength) {
                                while (cachedData.hashHistory.length > global.config.general.statsBufferLength) {
                                    cachedData.hashHistory.pop();
                                }
                            }
                            cachedData.minerHistory.unshift({ts: currentTime, cn: cachedData.minerCount});
                            if (cachedData.minerHistory.length > global.config.general.statsBufferLength) {
                                while (cachedData.minerHistory.length > global.config.general.statsBufferLength) {
                                    cachedData.minerHistory.pop();
                                }
                            }
                        }
                        // Calculate the average hashrate across all currently cached hash history
                        var totalCachedHashes = cachedData.hashHistory.reduce(function(a, b) { return {hs: a.hs + b.hs}; }, {hs: 0});
                        if (totalCachedHashes.hs > 0) {
                            cachedData.hashRateAvg = Math.floor(totalCachedHashes.hs / cachedData.hashHistory.length);
                        } else {
                            cachedData.hashRateAvg = 0;
                        }
                    } else {
                        cachedData = {
                            hash: Math.floor(localStats[key] / 600),
                            totalHashes: 0,
                            lastHash: localTimes[key],
                            minerCount: localMinerCount[key],
                            hashHistory: [{ts: currentTime, hs: cachedData.hash}],
                            minerHistory: [{ts: currentTime, cn: cachedData.hash}],
                            hashRateAvg: 0
                        };
                    }
                    cache_updates[key + "_stats"] = cachedData;
                });
                minerList.forEach(function (miner) {
                    if (globalMinerList.indexOf(miner) === -1) {
                        globalMinerList.push(miner);
                    }
                    if (miner.indexOf('_') === -1){
                        activeAddresses.push(miner);
                    }
                    let cachedData = global.database.getCache(miner);
                    if (cachedData !== false) {
                        cachedData.hash = Math.floor(localStats.miners[miner] / 600);
                        cachedData.pplnsShares = localStats.minersPplns[miner];
                        cachedData.lastHash = localTimes.miners[miner];
                        if (!cachedData.hasOwnProperty("hashHistory")) {
                            cachedData.hashHistory = [];
                        }
                        if (cycleCount === 0){
                            cachedData.hashHistory.unshift({ts: currentTime, hs: cachedData.hash});
                            if (cachedData.hashHistory.length > global.config.general.statsBufferLength) {
                                while (cachedData.hashHistory.length > global.config.general.statsBufferLength) {
                                    cachedData.hashHistory.pop();
                                }
                            }
                        }
                    } else {
                        cachedData = {
                            hash: Math.floor(localStats.miners[miner] / 600),
                            pplnsShares: localStats.minersPplns[miner],
                            totalHashes: 0,
                            lastHash: localTimes.miners[miner],
                            hashHistory: [{ts: currentTime, hs: cachedData.hash}],
                            goodShares: 0,
                            badShares: 0
                        };
                    }
                    cache_updates[miner] = cachedData;
                });
                globalMinerList.forEach(function (miner) {
                    if (minerList.indexOf(miner) === -1) {
                        let minerStats = global.database.getCache(miner);
                        if (minerStats.hash !== 0) {
                            console.log("Removing: " + miner + " as an active miner from the cache.");
                            if (miner.indexOf('_') > -1) {
                                // This is a worker case.
                                let address_parts = miner.split('_');
                                let address = address_parts[0];
                                let worker = address_parts[1];
                                global.mysql.query("SELECT email FROM users WHERE username = ? AND enable_email IS true limit 1", [address]).then(function (rows) {
                                    if (rows.length === 0) {
                                        return;
                                    }
                                    // toAddress, subject, body
                                    let emailData = {
                                        worker: worker,
                                        timestamp: global.support.formatDate(Date.now()),
                                        poolEmailSig: global.config.general.emailSig
                                    };
                                    global.support.sendEmail(rows[0].email,
                                        sprintf(global.config.email.workerNotHashingSubject, emailData),
                                        sprintf(global.config.email.workerNotHashingBody, emailData));
                                });
                            }
                            minerStats.hash = 0;
                            minerStats.pplnsShares = 0; // See Issue #5 for why we aren't tracking PPLNS statistics for inactive miners
                            cache_updates[miner] = minerStats;
                        }
                    }
                });
                Object.keys(identifiers).forEach(function (key) {
                    cache_updates[key + '_identifiers'] = identifiers[key];
                });
                cache_updates.minerList = globalMinerList;
                global.database.bulkSetCache(cache_updates);
                callback(null);
            });
        }
    ], function (err, result) {
        cycleCount += 1;
        if (cycleCount === 6){
            cycleCount = 0;
        }
    });
    setTimeout(updateShareStats, 10000);
}

function updatePoolStats(poolType) {
    let cache;
    if (typeof(poolType) !== 'undefined') {
        cache = global.database.getCache(poolType + "_stats");
    } else {
        cache = global.database.getCache("global_stats");
    }
    async.series([
        function (callback) {
            debug(threadName + "Checking Influx for last 10min avg for pool stats");
            return callback(null, cache.hash || 0);
        },
        function (callback) {
            debug(threadName + "Checking Influx for last 10min avg for miner count for pool stats");
            return callback(null, cache.minerCount || 0);
        },
        function (callback) {
            debug(threadName + "Checking Influx for last 10min avg for miner count for pool stats");
            return callback(null, cache.totalHashes || 0);
        },
        function (callback) {
            debug(threadName + "Checking MySQL for last block find time for pool stats");
            let cacheData = global.database.getBlockList(poolType);
            if (cacheData.length === 0) {
                return callback(null, 0);
            }
            return callback(null, Math.floor(cacheData[0].ts / 1000));
        },
        function (callback) {
            debug(threadName + "Checking MySQL for last block find time for pool stats");
            let cacheData = global.database.getBlockList(poolType);
            if (cacheData.length === 0) {
                return callback(null, 0);
            }
            return callback(null, cacheData[0].height);
        },
        function (callback) {
            debug(threadName + "Checking MySQL for block count for pool stats");
            return callback(null, global.database.getBlockList(poolType).length);
        },
        function (callback) {
            debug(threadName + "Checking MySQL for total miners paid");
            if (typeof(poolType) !== 'undefined') {
                global.mysql.query("SELECT payment_address, payment_id FROM payments WHERE pool_type = ? group by payment_address, payment_id", [poolType]).then(function (rows) {
                    return callback(null, rows.length);
                });
            } else {
                global.mysql.query("SELECT payment_address, payment_id FROM payments group by payment_address, payment_id").then(function (rows) {
                    return callback(null, rows.length);
                });
            }
        },
        function (callback) {
            debug(threadName + "Checking MySQL for total transactions count");
            if (typeof(poolType) !== 'undefined') {
                global.mysql.query("SELECT distinct(transaction_id) from payments WHERE pool_type = ?", [poolType]).then(function (rows) {
                    return callback(null, rows.length);
                });
            } else {
                global.mysql.query("SELECT count(id) as txn_count FROM transactions").then(function (rows) {
                    if (typeof(rows[0]) !== 'undefined') {
                        return callback(null, rows[0].txn_count);
                    } else {
                        return callback(null, 0);
                    }
                });
            }
        },
        function (callback) {
            debug(threadName + "Checking Influx for last 10min avg for miner count for pool stats");
            return callback(null, cache.roundHashes || 0);
        },
        function (callback) {
            debug(threadName + "Checking Influx for last 10min avg of pool hash rate for pool stats");
            return callback(null, cache.hashRateAvg || 0);
        },
        function (callback) {
            debug(threadName + "Checking Influx for lifetime pool average effort");
            let cacheData = global.database.getBlockList(poolType);
            if (cacheData.length === 0) {
                return callback(null, 0);
            }
            var totalShares = cacheData.reduce(function(a, b) { return {shares: a.shares + b.shares}; }, {shares: 0});
            var totalDiff = cacheData.reduce(function(a, b) { return {diff: a.diff + b.diff}; }, {diff: 0});
            var lifetimeEffort = ((totalShares.shares / totalDiff.diff) * 100).toFixed(2);
            return callback(null, lifetimeEffort);
        }
    ], function (err, result) {
        if (typeof(poolType) === 'undefined') {
            poolType = 'global';
        }
        global.database.setCache('pool_stats_' + poolType, {
            hashRate: result[0],
            miners: result[1],
            totalHashes: result[2],
            lastBlockFoundTime: result[3] || 0,
            lastBlockFound: result[4] || 0,
            totalBlocksFound: result[5] || 0,
            totalMinersPaid: result[6] || 0,
            totalPayments: result[7] || 0,
            roundHashes: result[8] || 0,
            hashRateAvg: result[9] || 0,
            lifetimeEffort: result[10] || 0
        });
    });
}

function updatePoolPorts(poolServers) {
    debug(threadName + "Updating pool ports");
    let local_cache = {global: []};
    let portCount = 0;
    global.mysql.query("select * from ports where hidden = 0 and lastSeen >= NOW() - INTERVAL 10 MINUTE").then(function (rows) {
        rows.forEach(function (row) {
            portCount += 1;
            if (!local_cache.hasOwnProperty(row.port_type)) {
                local_cache[row.port_type] = [];
            }
            local_cache[row.port_type].push({
                host: poolServers[row.pool_id],
                port: row.network_port,
                difficulty: row.starting_diff,
                description: row.description,
                miners: row.miners
            });
            if (portCount === rows.length) {
                let local_counts = {};
                let port_diff = {};
                let port_miners = {};
                let pool_type_count = 0;
                let localPortInfo = {};
                for (let pool_type in local_cache) { // jshint ignore:line
                    pool_type_count += 1;
                    local_cache[pool_type].forEach(function (portData) { // jshint ignore:line
                        if (!local_counts.hasOwnProperty(portData.port)) {
                            local_counts[portData.port] = 0;
                        }
                        if (!port_diff.hasOwnProperty(portData.port)) {
                            port_diff[portData.port] = portData.difficulty;
                        }
                        if (!port_miners.hasOwnProperty(portData.port)) {
                            port_miners[portData.port] = 0;
                        }
                        if (port_diff[portData.port] === portData.difficulty) {
                            local_counts[portData.port] += 1;
                            port_miners[portData.port] += portData.miners;
                        }
                        localPortInfo[portData.port] = portData.description;
                        if (local_counts[portData.port] === Object.keys(poolServers).length) {
                            local_cache.global.push({
                                host: {
                                    blockID: local_cache[pool_type][0].host.blockID,
                                    blockIDTime: local_cache[pool_type][0].host.blockIDTime,
                                    hostname: global.config.pool.geoDNS,
                                },
                                port: portData.port,
                                pool_type: pool_type,
                                difficulty: portData.difficulty,
                                miners: port_miners[portData.port],
                                description: localPortInfo[portData.port]
                            });
                        }
                    });
                    if (pool_type_count === Object.keys(local_cache).length) {
                        debug(threadName + "Sending the following to the workers: " + JSON.stringify(local_cache));
                        global.database.setCache('poolPorts', local_cache);
                    }
                }
            }
        });
    });
}

function updatePoolInformation() {
    let local_cache = {};
    debug(threadName + "Updating pool information");
    global.mysql.query("select * from pools where last_checkin >= NOW() - INTERVAL 10 MINUTE").then(function (rows) {
        rows.forEach(function (row) {
            local_cache[row.id] = {
                ip: row.ip,
                blockID: row.blockID,
                blockIDTime: global.support.formatDateFromSQL(row.blockIDTime),
                hostname: row.hostname
            };
            if (Object.keys(local_cache).length === rows.length) {
                global.database.setCache('poolServers', local_cache);
                updatePoolPorts(local_cache);
            }
        });
    });
}

function updateBlockHeader() {
    global.coinFuncs.getLastBlockHeader(function (err, blockHeader) {
        if (err !== null){
            return console.error(`Issue getting last block header: ${JSON.stringify(blockHeader)}`);
        }
        if (blockHeader.hash !== lastBlockHash) {
            lastBlockHash = blockHeader.hash;
            global.database.setCache('networkBlockInfo', {
                difficulty: blockHeader.difficulty,
                hash: blockHeader.hash,
                height: blockHeader.height,
                value: blockHeader.reward,
                ts: blockHeader.timestamp
            });
        } else if (blockHeader.hash === lastBlockHash) {
            debug("Block headers identical to historical header.  Ignoring");
        } else {
            console.error("GetLastBlockHeader Error during block header update");
        }
    });
}

function updateWalletStats() {
    async.waterfall([
        function (callback) {
            global.coinFuncs.getBalance(function (err, wallet) {
                if (err !== null){
                    return callback(true, "Unable to process balance");
                }

                return callback(null, {
                    balance: wallet.balance,
                    unlocked: wallet.unlocked_balance,
                    ts: Date.now()
                });
            });
        },
        function (state, callback) {
            global.coinFuncs.getHeight(function (err, wallet) {
                if (err !== null){
                    return callback(true, "Unable to get current wallet height");
                }

                return callback(null, wallet);
            });
        }
    ], function (err, results) {
        if (err) {
            return console.error("Unable to get wallet stats: " + results);
        }
        global.database.setCache('walletStateInfo', results);
        let history = global.database.getCache('walletHistory');
        if (history === false) {
            history = [];
        }
        history.unshift(results);
        history = history.sort(global.support.tsCompare);
        if (history.length > global.config.general.statsBufferLength) {
            while (history.length > global.config.general.statsBufferLength) {
                history.pop();
            }
        }
        global.database.setCache('walletHistory', history);
    });

}

let lastBlockCheckIsOk = true;
function monitorNodes() {
    global.coinFuncs.getLastBlockHeader((err, block) => {
        if (err !== null) {
            if (lastBlockCheckIsOk) {
                lastBlockCheckIsOk = false;
                global.support.sendEmail(
                    global.config.general.adminEmail,
                    global.config.hostname + ' - Failed to query daemon for last block header',
                    `The worker failed to return last block header. Please verify if the daemon is running properly.`
                );
            }
            return
        }
        if (!lastBlockCheckIsOk) {
            lastBlockCheckIsOk = true;
            global.support.sendEmail(
                global.config.general.adminEmail,
                global.config.hostname + ' - Quering daemon for last block header is back to normal',
                `An warning was sent to you indicating that the the worker failed to return the last block header.
                 The issue seems to be solved now.`
            );
        }
        let networkAgeThreshold = Date.now() - (global.config.coin.blockTargetTime * 1000 * 15);
        let currentBlockAge = block.timestamp * 1000;
        if (currentBlockAge <= networkAgeThreshold) {
            let networkAgeDifference = (Date.now() - currentBlockAge) / 1000;
            global.support.sendEmail(
                global.config.general.adminEmail,
                global.config.hostname + ' - Pool server may have a broken blockchain daemon',
                `The worker daemon has not seen a new block on the network in ${networkAgeDifference} seconds.
                 The configured coin for this pool expects a block every ${global.config.coin.blockTargetTime} seconds on average.
                 This may mean the blockchain daemon on the server is broken and unable to sync on the network. Please investigate.`
            );
        }
        const sql = 'SELECT blockID, hostname, ip FROM pools WHERE last_checkin > DATE_SUB(NOW(), INTERVAL 30 MINUTE)';
        global.mysql.query(sql).then(pools => {
            pools.forEach(({ blockID, hostname, ip }) => {
                if (blockID < block.height - 3) {
                    global.support.sendEmail(
                        global.config.general.adminEmail,
                        global.config.hostname + ' - Pool server is behind in blocks',
                        `The pool server: ${hostname} with IP: ${ip} is ${(block.height - blockID)} blocks behind.`
                    );
                }
            })
        });
        
    });
}

updateShareStats();
updateBlockHeader();
updatePoolStats();
updatePoolInformation();
updateWalletStats();
monitorNodes();
setInterval(updateBlockHeader, 10000);
setInterval(updatePoolStats, 5000);
setInterval(updatePoolStats, 5000, 'pplns');
setInterval(updatePoolStats, 5000, 'pps');
setInterval(updatePoolStats, 5000, 'solo');
setInterval(updatePoolInformation, 5000);
setInterval(updateWalletStats, 60000);
setInterval(monitorNodes, 300000);
