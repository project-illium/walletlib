[![Go](https://github.com/project-illium/walletlib/actions/workflows/go.yaml/badge.svg)](https://github.com/project-illium/walletlib/actions/workflows/go.yaml)
[![golangci-lint](https://github.com/project-illium/walletlib/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/project-illium/walletlib/actions/workflows/golangci-lint.yaml)

# walletlib
illium wallet library

This codebase provides wallet functionality for illium applications. It offers three different operating modes that
offer different tradeoffs and different levels of privacy.

### Internal Wallet
In this mode the wallet is used as an internal library for another application and the application passes blockchain
data into the wallet package using internal APIs. The wallet then computes and maintains its internal state.

Ilxd uses this mode for its own internal wallet. 

### RPC Wallet
This mode is similar to the Internal Wallet in that it ingests blockchain data, computes and maintains states on
the client side. However, it uses the gRPC API to connect to an instance of ilxd to fetch blockchain data allowing the 
wallet to be used as a standalone application.

This mode does require some degree of trust in the server that it will not lie about transactions. However, it does maximize privacy
vis-à-vis server as the server will not be able to learn anything about the wallet's internal state.

The downside of this mode is the client must download metadata for every block in the chain to computer its internal
state. This requires a fair amount of bandwidth usage and can take time to sync with the network.

### Lite Wallet
The lite wallet also connects to an ilxd node using the gRPC API but allows the server to decrypt its transactions, 
sacrificing privacy vis-à-vis the server for less client bandwidth usage and a faster user experience. 


The `BlockchainClient` interface is used to provide blockchain data to wallet and determine the operating mode. 
The three implementations can be found in the `client` package. They just need to be initialized by the application
and passed in as a startup option to the wallet. 
