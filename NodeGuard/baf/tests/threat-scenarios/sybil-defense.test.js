/**
 * Sybil Defense - Realistic Security Tests
 * 
 * Comprehensive testing of Sybil attack defense mechanisms based on actual BAF capabilities.
 * Tests focus on implemented features: rate limiting, transaction patterns, and basic clustering.
 * 
 * @author ajgc
 * @version 1.0
 * @coverage Rate limiting, transaction validation, basic identity patterns
 */

const { ethers } = require('ethers');
const axios = require('axios');

describe('[Sybil Defense] Realistic Security Tests', () => {
  let provider;
  let legitimateWallets;
  let sybilWallets;
  let bafClient;
  let chainId;

  const BAF_URL = process.env.BAF_URL || 'http://localhost:3000';
  const ETH_RPC_URL = process.env.ETH_RPC_URL || 'http://localhost:8545';

  beforeAll(async () => {
    provider = new ethers.JsonRpcProvider(ETH_RPC_URL);
    
    const network = await provider.getNetwork();
    chainId = Number(network.chainId);
    console.log(`[SETUP] Connected to blockchain - Chain ID: ${chainId}`);

    // Create legitimate user wallets
    legitimateWallets = [];
    const mnemonic = "test test test test test test test test test test test junk";
    const masterWallet = ethers.Wallet.fromPhrase(mnemonic);
    
    for (let i = 0; i < 5; i++) {
      const wallet = masterWallet.deriveChild(i).connect(provider);
      legitimateWallets.push(wallet);
    }

    // Create Sybil attack wallets
    sybilWallets = [];
    for (let i = 100; i < 130; i++) { // 30 Sybil identities - realistic attack size
      const wallet = masterWallet.deriveChild(i).connect(provider);
      sybilWallets.push(wallet);
    }

    console.log(`[SETUP] Created ${legitimateWallets.length} legitimate wallets`);
    console.log(`[SETUP] Created ${sybilWallets.length} Sybil attack wallets`);

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

  describe('Rate Limiting Against Sybil Attacks', () => {
    test('should block rapid transactions from multiple identities', async () => {
      console.log('[TEST] Testing transaction blocking against Sybil burst...');

      const sybilBatch = sybilWallets.slice(0, 10);
      const results = [];
      
      // Send rapid transactions from multiple Sybil identities
      for (let i = 0; i < sybilBatch.length; i++) {
        const sybilWallet = sybilBatch[i];
        
        const rapidTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: sybilWallet.address,
            to: legitimateWallets[0].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 1000 + i
        };

        try {
          const response = await bafClient.post('/rpc', rapidTx);
          results.push({
            success: true,
            blocked: !!response.data.error,
            error: response.data.error?.message || null,
            wallet: sybilWallet.address
          });
        } catch (error) {
          results.push({
            success: false,
            blocked: true,
            error: error.message,
            wallet: sybilWallet.address
          });
        }
      }

      const blockedTransactions = results.filter(r => r.blocked).length;

      console.log(`[RESULT] Blocking results:`);
      console.log(`   Total transactions: ${results.length}`);
      console.log(`   Blocked: ${blockedTransactions}`);

      // Should block majority of rapid burst attacks (80%+ effectiveness)
      expect(blockedTransactions).toBeGreaterThan(8);
    }, 60000);

    test('should demonstrate protection capabilities during Sybil attack', async () => {
      console.log('[TEST] Testing protection during Sybil attack...');

      // Legitimate user transaction
      const legitTx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: legitimateWallets[0].address,
          to: legitimateWallets[1].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: '0x0',
          chainId: `0x${chainId.toString(16)}`
        }],
        id: 2000
      };

      // Sybil burst attack
      const sybilPromises = [];
      for (let i = 0; i < 15; i++) {
        const sybilTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: sybilWallets[i].address,
            to: legitimateWallets[0].address,
            value: '0x1',
            gas: '0x5208',
            gasPrice: '0x1',
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 2100 + i
        };
        sybilPromises.push(bafClient.post('/rpc', sybilTx));
      }

      // Execute legitimate transaction alongside Sybil attack
      const [legitResult, ...sybilResults] = await Promise.all([
        bafClient.post('/rpc', legitTx),
        ...sybilPromises
      ]);

      const sybilBlocked = sybilResults.filter(r => r.data.error).length;

      console.log(`[RESULT] Protection results:`);
      console.log(`   Sybil attacks blocked: ${sybilBlocked}/15`);

      // Should block vast majority of Sybil burst (85%+ effectiveness)
      expect(sybilBlocked).toBeGreaterThan(12);
    }, 90000);
  });

  describe('Transaction Pattern Detection', () => {
    test('should detect suspicious identical transaction patterns', async () => {
      console.log('[TEST] Testing identical transaction pattern detection...');

      const results = [];
      
      // Create identical transactions from different Sybil identities
      for (let i = 0; i < 8; i++) {
        const identicalTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: sybilWallets[i].address,
            to: legitimateWallets[0].address,
            value: '0x2000000000000000', // Identical value
            gas: '0x5208', // Identical gas
            gasPrice: '0x4A817C800', // Identical gas price
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 3000 + i
        };

        try {
          const response = await bafClient.post('/rpc', identicalTx);
          results.push({
            blocked: !!response.data.error,
            error: response.data.error?.message || null
          });
        } catch (error) {
          results.push({
            blocked: true,
            error: error.message
          });
        }

        // Small delay to avoid pure rate limiting
        await new Promise(resolve => setTimeout(resolve, 500));
      }

      const blockedCount = results.filter(r => r.blocked).length;
      const patternDetection = results.some(r => 
        r.error && (
          r.error.toLowerCase().includes('pattern') ||
          r.error.toLowerCase().includes('duplicate') ||
          r.error.toLowerCase().includes('identical')
        )
      );

      console.log(`[RESULT] Pattern detection results:`);
      console.log(`   Blocked transactions: ${blockedCount}/8`);
      console.log(`   Pattern detection active: ${patternDetection}`);

      // Should block most identical patterns (75%+ effectiveness)
      expect(blockedCount).toBeGreaterThan(6);
    }, 120000);

    test('should detect dust transaction spam patterns', async () => {
      console.log('[TEST] Testing dust transaction spam detection...');

      const dustResults = [];
      
      // Send many small value transactions (dust spam)
      for (let i = 0; i < 12; i++) {
        const dustTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: sybilWallets[15 + i].address,
            to: legitimateWallets[1].address,
            value: '0x1', // Dust amount
            gas: '0x5208',
            gasPrice: '0x1', // Very low gas price
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 4000 + i
        };

        try {
          const response = await bafClient.post('/rpc', dustTx);
          dustResults.push({
            blocked: !!response.data.error,
            error: response.data.error?.message || null
          });
        } catch (error) {
          dustResults.push({
            blocked: true,
            error: error.message
          });
        }

        await new Promise(resolve => setTimeout(resolve, 300));
      }

      const dustBlocked = dustResults.filter(r => r.blocked).length;
      const spamDetection = dustResults.some(r => 
        r.error && (
          r.error.toLowerCase().includes('dust') ||
          r.error.toLowerCase().includes('spam') ||
          r.error.toLowerCase().includes('value')
        )
      );

      console.log(`[RESULT] Dust spam detection:`);
      console.log(`   Dust transactions blocked: ${dustBlocked}/12`);
      console.log(`   Spam detection active: ${spamDetection}`);

      // Should block majority of dust spam (80%+ effectiveness)
      expect(dustBlocked).toBeGreaterThan(9);
    }, 150000);
  });

  describe('Basic Identity Clustering', () => {
    test('should detect sequential address patterns', async () => {
      console.log('[TEST] Testing sequential address clustering...');

      // Use sequential Sybil wallets (they have sequential addresses)
      const sequentialSybils = sybilWallets.slice(0, 6);
      const results = [];

      for (let i = 0; i < sequentialSybils.length; i++) {
        const sequentialTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: sequentialSybils[i].address,
            to: legitimateWallets[2].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 5000 + i
        };

        try {
          const response = await bafClient.post('/rpc', sequentialTx);
          results.push({
            blocked: !!response.data.error,
            error: response.data.error?.message || null,
            address: sequentialSybils[i].address
          });
        } catch (error) {
          results.push({
            blocked: true,
            error: error.message,
            address: sequentialSybils[i].address
          });
        }

        await new Promise(resolve => setTimeout(resolve, 800));
      }

      const blockedCount = results.filter(r => r.blocked).length;
      const clusteringDetection = results.some(r => 
        r.error && (
          r.error.toLowerCase().includes('cluster') ||
          r.error.toLowerCase().includes('sequential') ||
          r.error.toLowerCase().includes('related')
        )
      );

      console.log(`[RESULT] Sequential clustering results:`);
      console.log(`   Blocked sequential addresses: ${blockedCount}/6`);
      console.log(`   Clustering detection: ${clusteringDetection}`);

      // Should detect sequential patterns (70%+ effectiveness)
      expect(blockedCount).toBeGreaterThan(4);
    }, 120000);
  });

  describe('Nonce Management Against Sybil', () => {
    test('should handle nonce reuse attempts from Sybil identities', async () => {
      console.log('[TEST] Testing nonce reuse detection...');

      const nonceSybils = sybilWallets.slice(20, 25);
      const results = [];

      // All Sybils try to use the same nonce
      for (let i = 0; i < nonceSybils.length; i++) {
        const nonceReuseTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: nonceSybils[i].address,
            to: legitimateWallets[3].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: '0x1', // Same nonce for all
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 6000 + i
        };

        try {
          const response = await bafClient.post('/rpc', nonceReuseTx);
          results.push({
            blocked: !!response.data.error,
            error: response.data.error?.message || null
          });
        } catch (error) {
          results.push({
            blocked: true,
            error: error.message
          });
        }
      }

      const nonceBlocked = results.filter(r => r.blocked).length;

      console.log(`[RESULT] Nonce reuse detection:`);
      console.log(`   Blocked nonce reuse: ${nonceBlocked}/5`);

      // Should block majority of nonce reuse attempts (80%+ effectiveness)
      expect(nonceBlocked).toBeGreaterThan(4);
    }, 90000);

    test('should detect gap nonce attacks', async () => {
      console.log('[TEST] Testing gap nonce attack detection...');

      const gapSybils = sybilWallets.slice(25, 28);
      const results = [];

      // Sybils try to use future nonces (creating gaps)
      for (let i = 0; i < gapSybils.length; i++) {
        const gapNonceTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: gapSybils[i].address,
            to: legitimateWallets[4].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: `0x${(10 + i).toString(16)}`, // Future nonces
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 7000 + i
        };

        try {
          const response = await bafClient.post('/rpc', gapNonceTx);
          results.push({
            blocked: !!response.data.error,
            error: response.data.error?.message || null
          });
        } catch (error) {
          results.push({
            blocked: true,
            error: error.message
          });
        }
      }

      const gapBlocked = results.filter(r => r.blocked).length;

      console.log(`[RESULT] Gap nonce detection:`);
      console.log(`   Blocked gap nonces: ${gapBlocked}/3`);

      // Should detect most gap nonce attacks (65%+ effectiveness)
      expect(gapBlocked).toBeGreaterThan(2);
    }, 60000);
  });

  describe('Resource Exhaustion Protection', () => {
    test('should protect against transaction pool flooding', async () => {
      console.log('[TEST] Testing transaction pool flooding protection...');

      const floodResults = [];
      const floodSybils = sybilWallets.slice(0, 20);

      // Attempt to flood with many transactions
      const floodPromises = floodSybils.map((sybil, i) => {
        const floodTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: sybil.address,
            to: legitimateWallets[0].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 8000 + i
        };

        return bafClient.post('/rpc', floodTx)
          .then(response => ({
            blocked: !!response.data.error,
            error: response.data.error?.message || null
          }))
          .catch(error => ({
            blocked: true,
            error: error.message
          }));
      });

      const results = await Promise.all(floodPromises);
      
      const floodBlocked = results.filter(r => r.blocked).length;
      const resourceProtection = results.some(r => 
        r.error && (
          r.error.toLowerCase().includes('limit') ||
          r.error.toLowerCase().includes('capacity') ||
          r.error.toLowerCase().includes('flood')
        )
      );

      console.log(`[RESULT] Flood protection results:`);
      console.log(`   Flood transactions blocked: ${floodBlocked}/20`);
      console.log(`   Resource protection active: ${resourceProtection}`);

      // Should block most flooding attempts (85%+ effectiveness)
      expect(floodBlocked).toBeGreaterThan(17);
    }, 180000);
  });

  describe('Chain ID Validation', () => {
    test('should reject transactions with invalid chain IDs from Sybil attackers', async () => {
      console.log('[TEST] Testing chain ID validation against Sybil attacks...');

      const chainSybils = sybilWallets.slice(28, 30);
      const results = [];

      // Sybils try different invalid chain IDs
      const invalidChainIds = ['0x1', '0x89', '0x0', '0xFFFF'];
      
      for (let i = 0; i < chainSybils.length; i++) {
        for (let j = 0; j < invalidChainIds.length; j++) {
          const invalidChainTx = {
            jsonrpc: '2.0',
            method: 'eth_sendTransaction',
            params: [{
              from: chainSybils[i].address,
              to: legitimateWallets[0].address,
              value: '0x1000000000000000',
              gas: '0x5208',
              gasPrice: '0x4A817C800',
              nonce: '0x0',
              chainId: invalidChainIds[j]
            }],
            id: 9000 + (i * 10) + j
          };

          try {
            const response = await bafClient.post('/rpc', invalidChainTx);
            results.push({
              blocked: !!response.data.error,
              error: response.data.error?.message || null,
              chainId: invalidChainIds[j]
            });
          } catch (error) {
            results.push({
              blocked: true,
              error: error.message,
              chainId: invalidChainIds[j]
            });
          }
        }
      }

      const chainBlocked = results.filter(r => r.blocked).length;

      console.log(`[RESULT] Chain ID validation:`);
      console.log(`   Invalid chain IDs blocked: ${chainBlocked}/${results.length}`);

      // Should block most invalid chain IDs (75%+ effectiveness)
      expect(chainBlocked).toBeGreaterThan(Math.floor(results.length * 0.75));
    }, 120000);
  });

  describe('Gas Price Manipulation Attacks', () => {
    test('should detect coordinated gas price manipulation from Sybil network', async () => {
      console.log('[TEST] Testing gas price manipulation detection...');

      const gasSybils = sybilWallets.slice(10, 18);
      const results = [];

      // Coordinated extremely low gas prices to clog network
      for (let i = 0; i < gasSybils.length; i++) {
        const lowGasTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: gasSybils[i].address,
            to: legitimateWallets[0].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x1', // Extremely low gas price
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 10000 + i
        };

        try {
          const response = await bafClient.post('/rpc', lowGasTx);
          results.push({
            blocked: !!response.data.error,
            error: response.data.error?.message || null
          });
        } catch (error) {
          results.push({
            blocked: true,
            error: error.message
          });
        }

        await new Promise(resolve => setTimeout(resolve, 200));
      }

      const gasManipBlocked = results.filter(r => r.blocked).length;

      console.log(`[RESULT] Gas manipulation detection:`);
      console.log(`   Low gas price attacks blocked: ${gasManipBlocked}/8`);

      // Should block majority of gas manipulation attempts (75%+ effectiveness)
      expect(gasManipBlocked).toBeGreaterThan(6);
    }, 90000);

    test('should detect gas limit abuse patterns', async () => {
      console.log('[TEST] Testing gas limit abuse detection...');

      const gasAbuseSybils = sybilWallets.slice(18, 23);
      const results = [];

      // Attempt to use excessive gas limits
      for (let i = 0; i < gasAbuseSybils.length; i++) {
        const gasAbuseTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: gasAbuseSybils[i].address,
            to: legitimateWallets[0].address,
            value: '0x1000000000000000',
            gas: '0x1C9C380', // Excessive gas limit (30M)
            gasPrice: '0x4A817C800',
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 11000 + i
        };

        try {
          const response = await bafClient.post('/rpc', gasAbuseTx);
          results.push({
            blocked: !!response.data.error,
            error: response.data.error?.message || null
          });
        } catch (error) {
          results.push({
            blocked: true,
            error: error.message
          });
        }
      }

      const gasAbuseBlocked = results.filter(r => r.blocked).length;

      console.log(`[RESULT] Gas abuse detection:`);
      console.log(`   Gas limit abuse blocked: ${gasAbuseBlocked}/5`);

      // Should block most gas abuse attempts (80%+ effectiveness)
      expect(gasAbuseBlocked).toBeGreaterThan(4);
    }, 60000);
  });

  describe('Value Transfer Patterns', () => {
    test('should detect suspicious round-number value patterns', async () => {
      console.log('[TEST] Testing round-number value pattern detection...');

      const valueSybils = sybilWallets.slice(5, 12);
      const results = [];
      const suspiciousValues = [
        '0x16345785D8A0000', // Exactly 0.1 ETH
        '0x16345785D8A0000', // Exactly 0.1 ETH (repeated)
        '0x2386F26FC10000',  // Exactly 0.01 ETH
        '0x2386F26FC10000',  // Exactly 0.01 ETH (repeated)
        '0x38D7EA4C68000',   // Exactly 0.001 ETH
        '0x38D7EA4C68000',   // Exactly 0.001 ETH (repeated)
        '0x5AF3107A4000'     // Exactly 0.0001 ETH
      ];

      for (let i = 0; i < valueSybils.length; i++) {
        const roundValueTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: valueSybils[i].address,
            to: legitimateWallets[1].address,
            value: suspiciousValues[i],
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 12000 + i
        };

        try {
          const response = await bafClient.post('/rpc', roundValueTx);
          results.push({
            blocked: !!response.data.error,
            error: response.data.error?.message || null,
            value: suspiciousValues[i]
          });
        } catch (error) {
          results.push({
            blocked: true,
            error: error.message,
            value: suspiciousValues[i]
          });
        }

        await new Promise(resolve => setTimeout(resolve, 400));
      }

      const roundValueBlocked = results.filter(r => r.blocked).length;

      console.log(`[RESULT] Round value pattern detection:`);
      console.log(`   Round value patterns blocked: ${roundValueBlocked}/7`);

      // Should detect suspicious round-number patterns (70%+ effectiveness)
      expect(roundValueBlocked).toBeGreaterThan(5);
    }, 90000);
  });

  describe('Cross-Identity Coordination Detection', () => {
    test('should detect coordinated timing attacks', async () => {
      console.log('[TEST] Testing coordinated timing attack detection...');

      const timingSybils = sybilWallets.slice(2, 10);
      const results = [];

      // All Sybils attack at exactly the same time
      const coordinatedPromises = timingSybils.map((sybil, i) => {
        const coordTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: sybil.address,
            to: legitimateWallets[2].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 13000 + i
        };

        return bafClient.post('/rpc', coordTx)
          .then(response => ({
            blocked: !!response.data.error,
            error: response.data.error?.message || null
          }))
          .catch(error => ({
            blocked: true,
            error: error.message
          }));
      });

      const coordResults = await Promise.all(coordinatedPromises);
      const coordBlocked = coordResults.filter(r => r.blocked).length;

      console.log(`[RESULT] Coordinated timing detection:`);
      console.log(`   Coordinated attacks blocked: ${coordBlocked}/8`);

      // Should detect coordinated timing patterns (85%+ effectiveness)
      expect(coordBlocked).toBeGreaterThan(6);
    }, 60000);

    test('should detect wallet creation patterns', async () => {
      console.log('[TEST] Testing wallet creation pattern detection...');

      // Use freshly created wallets to simulate new Sybil identities
      const freshSybils = [];
      const baseKey = ethers.randomBytes(32);
      
      for (let i = 0; i < 6; i++) {
        const derivedKey = ethers.keccak256(
          ethers.concat([baseKey, ethers.toBeArray(i)])
        );
        const wallet = new ethers.Wallet(derivedKey, provider);
        freshSybils.push(wallet);
      }

      const results = [];

      for (let i = 0; i < freshSybils.length; i++) {
        const newWalletTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: freshSybils[i].address,
            to: legitimateWallets[3].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 14000 + i
        };

        try {
          const response = await bafClient.post('/rpc', newWalletTx);
          results.push({
            blocked: !!response.data.error,
            error: response.data.error?.message || null,
            address: freshSybils[i].address
          });
        } catch (error) {
          results.push({
            blocked: true,
            error: error.message,
            address: freshSybils[i].address
          });
        }

        await new Promise(resolve => setTimeout(resolve, 300));
      }

      const newWalletBlocked = results.filter(r => r.blocked).length;

      console.log(`[RESULT] New wallet pattern detection:`);
      console.log(`   New wallet attacks blocked: ${newWalletBlocked}/6`);

      // Should detect suspicious new wallet patterns (65%+ effectiveness)
      expect(newWalletBlocked).toBeGreaterThan(4);
    }, 90000);
  });

  describe('Advanced Sybil Evasion Attempts', () => {
    test('should detect randomized delay evasion attempts', async () => {
      console.log('[TEST] Testing randomized delay evasion detection...');

      const evasionSybils = sybilWallets.slice(12, 18);
      const results = [];

      // Attempt evasion with randomized delays and slight variations
      for (let i = 0; i < evasionSybils.length; i++) {
        const randomDelay = Math.floor(Math.random() * 1000) + 500; // 500-1500ms
        const randomValue = `0x${(BigInt('0x1000000000000000') + BigInt(Math.floor(Math.random() * 1000))).toString(16)}`;
        
        await new Promise(resolve => setTimeout(resolve, randomDelay));

        const evasionTx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: evasionSybils[i].address,
            to: legitimateWallets[4].address,
            value: randomValue,
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: '0x0',
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 15000 + i
        };

        try {
          const response = await bafClient.post('/rpc', evasionTx);
          results.push({
            blocked: !!response.data.error,
            error: response.data.error?.message || null
          });
        } catch (error) {
          results.push({
            blocked: true,
            error: error.message
          });
        }
      }

      const evasionBlocked = results.filter(r => r.blocked).length;

      console.log(`[RESULT] Evasion attempt detection:`);
      console.log(`   Evasion attempts blocked: ${evasionBlocked}/6`);

      // Should still detect sophisticated evasion attempts (60%+ effectiveness)
      expect(evasionBlocked).toBeGreaterThan(3);
    }, 120000);
  });

  afterAll(async () => {
    console.log('[CLEANUP] Sybil defense tests completed');
  });
});
