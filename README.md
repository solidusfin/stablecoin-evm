
# StableToken Project

A fully compliant, upgradeable ERC-20 stabletoken implementation built on Ethereum using the OpenZeppelin library and Foundry development framework.

## Overview

This project implements a stabletoken with the following features:
- ERC-20 compliant token
- Upgradeable architecture using OpenZeppelin's proxy pattern
- Role-based access control
- Minting and burning capabilities
- EIP-2612 permit support
- EIP-3009 signature tansaction support

## Contract Architecture

### Core Contracts

1. **StableTokenV1**: The initial implementation of the stabletoken token
   - Implements ERC-20 standard and its extended functions
   - Includes pausable functionality
   - Supports upgradeable pattern


## Development Setup

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Solidity 0.8.28

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd stabletoken
```

2. Install dependencies:
```bash
forge soldeer install
```

### Build

Compile the contracts:
```bash
forge build
```

### Deployment

Deploy to a network:
```bash
forge script script/Deploy.s.sol --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
```

### Verification
Verify the contract on Etherscan:
```bash
forge verify-contract <CONTRACT_ADDRESS> --rpc-url <RPC_URL> --etherscan-api-key <ETHERSCAN_API_KEY>
```

**Note:**
- Replace `<RPC_URL>` with the RPC URL of the network you want to verify on.
- Replace `<PRIVATE_KEY>` with your private key for the deployment.
- Replace `<ETHERSCAN_API_KEY>` with your Etherscan API key.
- Replace `<CONTRACT_ADDRESS>` with the actual contract address.
- Optionally use environment variables to configure the above parameters.
- use the --constructor-args parameter to verify contracts with parameters.

## Project Structure

```
stabletoken/
├── src/                    # Source contracts
│   ├── StableTokenV1.sol   # Initial token implementation
│   ├── interfaces/         # Contract interfaces
│   └── libraries/          # Utility libraries
├── script/                 # Deployment scripts
│   ├── Base.s.sol          # Base script functionality
│   ├── Deploy.s.sol        # Initial deployment script
├── foundry.toml            # Foundry configuration
└── remappings.txt          # Dependency remappings
```

## Technical Details

### Upgradeability

The project uses the UUPS (Universal Upgradeable Proxy Standard) pattern from OpenZeppelin. This allows for upgrading the contract logic while preserving the contract state and address.

### Access Control

Role-based access control is implemented with the following roles:
- ADMIN-ROLE: assign and manage all other roles
- UPGRADER_ROLE: upgrade contracts
- PAUSER_ROLE: pause and restore contracts
- RESCUER_ROLE: recover accidentally received tokens
- BLACKLISTER_ROLE: blacklist manager
- MAIN_MINTER_ROLE: assign and manage MINTER_ROLE roles
- MINTER_ROLE: mint and destroy tokens

### Minting Process

- The main minter configure other minters with specific allowances
- other minters can mint tokens up to their allowance
- The main minter can increase or decrease other minters allowances

### Security Features

- Pausable functionality to stop transfers in emergency situations
- Role separation to limit the impact of compromised accounts

### interfaces

| Interface Name | Interface Type | whenNotPaused | notBlacklisted |
|---------|---------|-------------------|---------------------|
| initialize | Write | No | No |
| upgradeToAndCall | Write | No | No |
| pause | Write | Yes | No |
| unpause | Write | No | No |
| rescueERC20 | Write | No | No |
| mint | Write | Yes | Yes |
| burn | Write | Yes | Yes |
| approve | Write | Yes | Yes |
| permit | Write | Yes | Yes |
| increaseAllowance | Write | Yes | Yes |
| decreaseAllowance | Write | Yes | Yes |
| transfer | Write | Yes | Yes |
| transferFrom | Write | Yes | Yes |
| transferWithAuthorization | Write | Yes | Yes |
| receiveWithAuthorization | Write | Yes | Yes |
| cancelAuthorization | Write | Yes | No |
| grantRole | Write | No | No |
| revokeRole | Write | No | No |
| renounceRole | Write | No | No |
| blacklist | Write | No | No |
| unblacklist | Write | No | No |
| configureMinter | Write | Yes | No |
| removeMinter | Write | No | No |
| name | Read | No | No |
| symbol | Read | No | No |
| version | Read | No | No |
| decimals | Read | No | No |
| totalSupply | Read | No | No |
| balanceOf | Read | No | No |
| allowance | Read | No | No |
| nonces | Read | No | No |
| hasRole | Read | No | No |
| getRoleAdmin | Read | No | No |
| isBlacklisted | Read | No | No |
| isMinter | Read | No | No |
| minterAllowance | Read | No | No |
| authorizationState | Read | No | No |
| paused | Read | No | No |
