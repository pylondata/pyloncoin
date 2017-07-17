// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

/** The maximum allowed number of transactions in a block */
static const unsigned int MAX_TX_PER_BLOCK = 20000;

/** The maximum allowed number of signature check operations in a block (network rule) */
#define MAX_BLOCK_SIGOPS (dynParams.nMaxBlockSize/50)

/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
#define COINBASE_MATURITY (dynParams.nCoinbaseMaturity)

/** The maximum allowed number if active CVNs */
static const unsigned int MAX_NUMBER_OF_CVNS = 100;

/** The maximum allowed number if active chain admins */
static const unsigned int MAX_NUMBER_OF_CHAIN_ADMINS = 11;

/** Flags for LockTime() */
enum {
    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
