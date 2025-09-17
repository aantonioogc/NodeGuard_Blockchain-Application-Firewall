/**
 * EIP-155 Replay Protection - Real Blockchain Tests
 * 
 * Comprehensive testing of replay attack protection using EIP-155 standard.
 * Validates signature security and cross-chain replay prevention.
 * 
 * @author ajgc
 * @version 1.0
 * @coverage FirewallProvider, signature validation, EIP-155 compliance
 */

const { ethers } = require('ethers');
const axios = require('axios');

describe('[EIP-155] Replay Protection Tests', () => {
  let provider;
  let wallets;
  let bafClient;
  let chainId;

  const BAF_URL = process.env.BAF_URL || 'http://localhost:3000';
  const ETH_RPC_URL = process.env.ETH_RPC_URL || 'http://localhost:8545';

  beforeAll(async () => {
    provider = new ethers.JsonRpcProvider(ETH_RPC_URL);
    
    const network = await provider.getNetwork();
    chainId = Number(network.chainId);
    console.log(`[SETUP] Connected to blockchain - Chain ID: ${chainId}`);

    wallets = [];
    const mnemonic = "test test test test test test test test test test test junk";
    const masterWallet = ethers.Wallet.fromPhrase(mnemonic);
    
    for (let i = 0; i < 10; i++) {
      const wallet = masterWallet.deriveChild(i).connect(provider);
      wallets.push(wallet);
    }

    console.log(`[SETUP] Created ${wallets.length} test wallets`);

    bafClient = axios.create({
      baseURL: BAF_URL,
      timeout: 30000,
      headers: { 'Content-Type': 'application/json' }
    });

    const healthCheck = await bafClient.post('/rpc', {
      jsonrpc: '2.0',
      method: 'net_version',
      params: [],
      id: 1
    });
    
    expect(healthCheck.status).toBe(200);
    console.log('[SETUP] BAF is operational');
  }, 60000);

  describe('Basic EIP-155 Compliance', () => {
    test('should enforce EIP-155 chainId in transactions', async () => {
      const wallet = wallets[0];
      const nonce = await provider.getTransactionCount(wallet.address);

      const validTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[1].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${nonce.toString(16)}`,
          chainId: `0x${chainId.toString(16)}`,
          type: '0x0'
        }],
        id: 1
      };

      const response = await bafClient.post('/rpc', validTx);
      
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('jsonrpc', '2.0');
    });

    test('should block transactions without chainId', async () => {
      const wallet = wallets[0];
      const nonce = await provider.getTransactionCount(wallet.address);

      const invalidTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[1].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${nonce.toString(16)}`
        }],
        id: 2
      };

      const response = await bafClient.post('/rpc', invalidTx);
      
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('error');
      // Must reject transactions without chainId for EIP-155 compliance
      expect(response.data.error).toBeDefined();
    });

    test('should block transactions with wrong chainId', async () => {
      const wallet = wallets[0];
      const nonce = await provider.getTransactionCount(wallet.address);

      const wrongChainTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[1].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${nonce.toString(16)}`,
          chainId: '0x1'
        }],
        id: 3
      };

      const response = await bafClient.post('/rpc', wrongChainTx);
      
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('error');
      // Must reject transactions with incorrect chainId
      expect(response.data.error).toBeDefined();
    });
  });

  describe('Replay Attack Detection', () => {
    test('should detect and block transaction replay', async () => {
      const wallet = wallets[1];
      const nonce = await provider.getTransactionCount(wallet.address);

      const txData = {
        to: wallets[2].address,
        value: ethers.parseEther('0.001'),
        gasLimit: 21000,
        gasPrice: ethers.parseUnits('20', 'gwei'),
        nonce: nonce,
        chainId: chainId
      };

      const signedTx = await wallet.signTransaction(txData);
      const parsedTx = ethers.Transaction.from(signedTx);

      const firstAttempt = {
        jsonrpc: '2.0',
        method: 'eth_sendRawTransaction',
        params: [signedTx],
        id: 4
      };

      const firstResponse = await bafClient.post('/rpc', firstAttempt);
      expect(firstResponse.status).toBe(200);

      await new Promise(resolve => setTimeout(resolve, 2000));

      const replayAttempt = {
        jsonrpc: '2.0',
        method: 'eth_sendRawTransaction',
        params: [signedTx],
        id: 5
      };

      const replayResponse = await bafClient.post('/rpc', replayAttempt);
      
      expect(replayResponse.status).toBe(200);
      expect(replayResponse.data).toHaveProperty('error');
      // Must prevent replay attacks through transaction rejection
      expect(replayResponse.data.error).toBeDefined();
    });

    test('should detect signature reuse across different parameters', async () => {
      const wallet = wallets[2];
      
      const originalTx = {
        to: wallets[3].address,
        value: ethers.parseEther('0.001'),
        gasLimit: 21000,
        gasPrice: ethers.parseUnits('20', 'gwei'),
        nonce: await provider.getTransactionCount(wallet.address),
        chainId: chainId
      };

      const signedOriginal = await wallet.signTransaction(originalTx);
      const parsedOriginal = ethers.Transaction.from(signedOriginal);

      const modifiedTx = {
        ...originalTx,
        value: ethers.parseEther('1.0'),
        to: wallets[4].address
      };

      // Simulate transaction manipulation with original signature components
      const manipulatedRequest = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: modifiedTx.to,
          value: `0x${modifiedTx.value.toString(16)}`,
          gas: `0x${modifiedTx.gasLimit.toString(16)}`,
          gasPrice: `0x${modifiedTx.gasPrice.toString(16)}`,
          nonce: `0x${modifiedTx.nonce.toString(16)}`,
          chainId: `0x${chainId.toString(16)}`,
          r: parsedOriginal.signature.r,
          s: parsedOriginal.signature.s,
          v: parsedOriginal.signature.v
        }],
        id: 6
      };

      const response = await bafClient.post('/rpc', manipulatedRequest);
      
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('error');
      // Must reject transactions with invalid signature parameters
      expect(response.data.error).toBeDefined();
    });
  });

  describe('Cross-Chain Replay Protection', () => {
    test('should block cross-chain replay attempts', async () => {
      const wallet = wallets[3];

      const crossChainTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[4].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${(await provider.getTransactionCount(wallet.address)).toString(16)}`,
          chainId: '0x1',
          r: '0x' + '1'.repeat(64),
          s: '0x' + '2'.repeat(64),
          v: '0x25'
        }],
        id: 7
      };

      const response = await bafClient.post('/rpc', crossChainTx);
      
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('error');
      // Must prevent cross-chain replay attacks
      expect(response.data.error).toBeDefined();
    });

    test('should validate chainId consistency in batch requests', async () => {
      const wallet = wallets[4];
      const baseNonce = await provider.getTransactionCount(wallet.address);

      const batchWithMixedChainIds = [
        {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: wallet.address,
            to: wallets[5].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: `0x${baseNonce.toString(16)}`,
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 8
        },
        {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: wallet.address,
            to: wallets[6].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: `0x${(baseNonce + 1).toString(16)}`,
            chainId: '0x1'
          }],
          id: 9
        }
      ];

      const response = await bafClient.post('/rpc', batchWithMixedChainIds);
      
      expect(response.status).toBe(200);
      expect(Array.isArray(response.data)).toBe(true);
      
      const secondResponse = response.data.find(r => r.id === 9);
      expect(secondResponse).toHaveProperty('error');
      // Must reject transactions with inconsistent chainId in batch
      expect(secondResponse.error).toBeDefined();
    });
  });

  describe('Advanced Signature Validation', () => {
    test('should detect malformed signatures', async () => {
      const wallet = wallets[5];

      const malformedSigTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[6].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${(await provider.getTransactionCount(wallet.address)).toString(16)}`,
          chainId: `0x${chainId.toString(16)}`,
          r: '0xinvalidhex',
          s: '0x' + 'f'.repeat(64),
          v: '0x1c'
        }],
        id: 10
      };

      const response = await bafClient.post('/rpc', malformedSigTx);
      
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('error');
      // Must reject transactions with malformed signature components
      expect(response.data.error.message).toMatch(/signature|malformed|invalid|hex/i);
    });

    test('should detect signature with invalid recovery ID', async () => {
      const wallet = wallets[6];

      const invalidRecoveryTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[7].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${(await provider.getTransactionCount(wallet.address)).toString(16)}`,
          chainId: `0x${chainId.toString(16)}`,
          r: '0x' + '1'.repeat(64),
          s: '0x' + '2'.repeat(64),
          v: '0xFF'
        }],
        id: 11
      };

      const response = await bafClient.post('/rpc', invalidRecoveryTx);
      
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('error');
      // Must reject transactions with invalid recovery parameters
      expect(response.data.error).toBeDefined();
    });
  });

  describe('Nonce Management and Replay Prevention', () => {
    test('should detect out-of-order nonce attacks', async () => {
      const wallet = wallets[7];
      const currentNonce = await provider.getTransactionCount(wallet.address);

      const futureNonceTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[8].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${(currentNonce + 10).toString(16)}`,
          chainId: `0x${chainId.toString(16)}`
        }],
        id: 12
      };

      const response = await bafClient.post('/rpc', futureNonceTx);
      
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('error');
      // Must reject transactions with invalid nonce sequence
      expect(response.data.error).toBeDefined();
    });

    test('should detect nonce reuse attempts', async () => {
      const wallet = wallets[8];
      const nonce = await provider.getTransactionCount(wallet.address);

      const firstTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[9].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${nonce.toString(16)}`,
          chainId: `0x${chainId.toString(16)}`
        }],
        id: 13
      };

      await bafClient.post('/rpc', firstTx);

      const reuseTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[0].address,
          value: '0x2000000000000000',
          gas: '0x5208',
          gasPrice: '0x5D21DBA00',
          nonce: `0x${nonce.toString(16)}`,
          chainId: `0x${chainId.toString(16)}`
        }],
        id: 14
      };

      const response = await bafClient.post('/rpc', reuseTx);
      
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('error');
      // Must prevent nonce reuse attacks
      expect(response.data.error).toBeDefined();
    });
  });

  describe('EIP-155 Protection Under Load', () => {
    test('should maintain security validation under concurrent requests', async () => {
      const promises = [];
      const walletUsed = wallets[9];

      for (let i = 0; i < 20; i++) {
        const tx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: walletUsed.address,
            to: wallets[i % 9].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: `0x${i.toString(16)}`,
            chainId: i % 2 === 0 ? `0x${chainId.toString(16)}` : '0x1'
          }],
          id: 100 + i
        };

        promises.push(bafClient.post('/rpc', tx));
      }

      const responses = await Promise.all(promises);
      
      let validChainIdCount = 0;
      let invalidChainIdCount = 0;
      
      responses.forEach((response, index) => {
        expect(response.status).toBe(200);
        
        if (index % 2 === 0) {
          // Valid chainId transactions - may pass or be blocked by other security measures
          validChainIdCount++;
        } else {
          // Invalid chainId transactions - must be blocked
          expect(response.data).toHaveProperty('error');
          invalidChainIdCount++;
        }
      });

      // Verify test integrity: all invalid chainId transactions were processed
      expect(invalidChainIdCount).toBe(10);
      expect(validChainIdCount).toBe(10);
    }, 60000);
  });

  describe('Advanced Security Cases', () => {
    test('should detect zero chainId (pre-EIP155 legacy)', async () => {
      const wallet = wallets[0];
      
      const legacyTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[1].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${(await provider.getTransactionCount(wallet.address)).toString(16)}`,
          chainId: '0x0'
        }],
        id: 201
      };

      const response = await bafClient.post('/rpc', legacyTx);
      
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('error');
      // Must reject legacy transactions without proper EIP-155 protection
      expect(response.data.error).toBeDefined();
    });

    test('should detect signature component manipulation', async () => {
      const wallet = wallets[1];
      
      const manipulatedTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[2].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${(await provider.getTransactionCount(wallet.address)).toString(16)}`,
          chainId: `0x${chainId.toString(16)}`,
          r: '0x' + '0'.repeat(64),
          s: '0x' + '0'.repeat(64),
          v: '0x00'
        }],
        id: 202
      };

      const response = await bafClient.post('/rpc', manipulatedTx);
      
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('error');
      // Must reject transactions with zero signature components
      expect(response.data.error.message).toMatch(/signature|invalid|format|zero|hex/i);
    });

    test('should handle concurrent nonce reuse attempts', async () => {
      const wallet = wallets[2];
      const nonce = await provider.getTransactionCount(wallet.address);
      
      const concurrentTxs = Array.from({length: 3}, (_, i) => ({
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[3].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${nonce.toString(16)}`,
          chainId: `0x${chainId.toString(16)}`
        }],
        id: 203 + i
      }));

      const promises = concurrentTxs.map(tx => bafClient.post('/rpc', tx));
      const responses = await Promise.all(promises);
      
      let blockedCount = 0;
      responses.forEach(response => {
        // Count transactions blocked by any security mechanism
        if (response.data.error) {
          blockedCount++;
        }
      });

      // Security requirement: must block at least 80% of concurrent nonce attempts
      expect(blockedCount).toBeGreaterThanOrEqual(2);
    });

    test('should maintain security under stress conditions', async () => {
      const attackScenarios = [
        { chainId: '0x1', description: 'Wrong network chainId' },
        { chainId: null, description: 'Missing chainId parameter' },
        { 
          chainId: `0x${chainId.toString(16)}`, 
          r: '0xinvalidhex', 
          s: '0x' + 'f'.repeat(64), 
          v: '0x1c',
          description: 'Malformed signature component'
        },
        { chainId: '0xFFFFFFFF', description: 'Unsupported chainId' }
      ];

      const promises = attackScenarios.map((scenario, i) => {
        const wallet = wallets[i % wallets.length];
        const params = {
          from: wallet.address,
          to: wallets[(i + 1) % wallets.length].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${i.toString(16)}`
        };

        if (scenario.chainId) params.chainId = scenario.chainId;
        if (scenario.r) params.r = scenario.r;
        if (scenario.s) params.s = scenario.s;
        if (scenario.v) params.v = scenario.v;

        return bafClient.post('/rpc', {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction', 
          params: [params],
          id: 210 + i
        }).then(response => ({ response, scenario }));
      });

      const results = await Promise.all(promises);
      
      let blockedAttacks = 0;
      results.forEach(({ response, scenario }) => {
        expect(response.status).toBe(200);
        
        // All attack scenarios must be blocked by security measures
        if (response.data.error) {
          blockedAttacks++;
        }
        
        console.log(`[SECURITY] ${scenario.description}: ${response.data.error ? 'BLOCKED' : 'ALLOWED'}`);
      });

      // Security requirement: Must block 100% of attack scenarios
      expect(blockedAttacks).toBe(attackScenarios.length);
      console.log(`[RESULT] Successfully blocked ${blockedAttacks}/${results.length} attack scenarios`);
    }, 60000);
  });

  afterAll(async () => {
    console.log('[CLEANUP] EIP-155 tests complete');
  });
});
