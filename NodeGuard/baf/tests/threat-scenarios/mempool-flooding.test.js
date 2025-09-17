/**
 * Mempool Flooding Protection - Real Blockchain Tests
 * 
 * Valida la detección y bloqueo de ataques de flooding en la mempool.
 * Cubre ráfagas, repetición, volumen anómalo y activación de circuit breaker.
 * 
 * @author ajgc
 * @version 1.0
 * @coverage FirewallProvider, rate limiting, circuit breaker, DoS detection
 */

const { ethers } = require('ethers');
const axios = require('axios');

describe('[Mempool Flooding] Protection Tests', () => {
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

    wallets = [];
    const mnemonic = "test test test test test test test test test test test junk";
    const masterWallet = ethers.Wallet.fromPhrase(mnemonic);
    for (let i = 0; i < 5; i++) {
      const wallet = masterWallet.deriveChild(i).connect(provider);
      wallets.push(wallet);
    }

    bafClient = axios.create({
      baseURL: BAF_URL,
      timeout: 30000,
      headers: { 'Content-Type': 'application/json' }
    });

    // Health check
    const healthCheck = await bafClient.post('/rpc', {
      jsonrpc: '2.0',
      method: 'net_version',
      params: [],
      id: 1
    });
    expect(healthCheck.status).toBe(200);
  }, 30000);

  test('should block burst of transactions from single IP (flooding)', async () => {
    const wallet = wallets[0];
    const nonce = await provider.getTransactionCount(wallet.address);
    const clientIp = '203.0.113.45';

    let blocked = 0;
    let allowed = 0;
    const total = 30;

    for (let i = 0; i < total; i++) {
      const tx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[1].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${(nonce + i).toString(16)}`,
          chainId: `0x${chainId.toString(16)}`
        }],
        id: 100 + i
      };

      const response = await bafClient.post('/rpc', tx, {
        headers: {
          'X-Forwarded-For': clientIp,
          'X-Real-IP': clientIp
        }
      });

      if (response.data.error) blocked++;
      else allowed++;
      await new Promise(res => setTimeout(res, 50)); // Simula ráfaga
    }

    console.log(`[RESULT] Flooding: ${blocked}/${total} bloqueadas, ${allowed} permitidas`);
    expect(blocked).toBeGreaterThanOrEqual(Math.floor(total * 0.6)); // Al menos 60% bloqueadas
  }, 60000);

  test('should activate circuit breaker on sustained flooding', async () => {
    const wallet = wallets[2];
    const nonce = await provider.getTransactionCount(wallet.address);
    const clientIp = '198.51.100.78';

    let circuitBreakerTriggered = false;
    for (let i = 0; i < 20; i++) {
      const tx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[3].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${(nonce + i).toString(16)}`,
          chainId: `0x${chainId.toString(16)}`
        }],
        id: 200 + i
      };

      const response = await bafClient.post('/rpc', tx, {
        headers: {
          'X-Forwarded-For': clientIp,
          'X-Real-IP': clientIp
        }
      });

      let errorMsg = '';
      if (response.data.error) {
        if (typeof response.data.error === 'string') errorMsg = response.data.error;
        else if (response.data.error.message) errorMsg = response.data.error.message;
        else errorMsg = JSON.stringify(response.data.error);
        if (errorMsg.toLowerCase().includes('circuit breaker')) {
          circuitBreakerTriggered = true;
          break;
        }
      }
      await new Promise(res => setTimeout(res, 30));
    }

    expect(circuitBreakerTriggered).toBe(true);
  }, 40000);

  test('should block flooding from multiple IPs', async () => {
    let blocked = 0;
    const total = wallets.length * 5;
    for (let i = 0; i < wallets.length; i++) {
      const wallet = wallets[i];
      const nonce = await provider.getTransactionCount(wallet.address);
      const clientIp = `203.0.113.${45 + i}`;
      for (let j = 0; j < 5; j++) {
        const tx = {
          jsonrpc: '2.0',
          method: 'eth_sendTransaction',
          params: [{
            from: wallet.address,
            to: wallets[(i+1)%wallets.length].address,
            value: '0x1000000000000000',
            gas: '0x5208',
            gasPrice: '0x4A817C800',
            nonce: `0x${(nonce + j).toString(16)}`,
            chainId: `0x${chainId.toString(16)}`
          }],
          id: 400 + i*5 + j
        };
        const response = await bafClient.post('/rpc', tx, {
          headers: {
            'X-Forwarded-For': clientIp,
            'X-Real-IP': clientIp
          }
        });
        if (response.data.error) blocked++;
        await new Promise(res => setTimeout(res, 30));
      }
    }
    console.log(`[RESULT] Flooding from multiple IPs: ${blocked}/${total} bloqueadas`);
    expect(blocked).toBeGreaterThanOrEqual(Math.floor(total * 0.6));
  }, 40000);

  // --- Additional Coverage Tests ---
  test('should rate limit eth_call requests from single IP', async () => {
    const clientIp = '192.0.2.123';
    let blocked = 0;
    let allowed = 0;
    for (let i = 0; i < 20; i++) {
      const req = {
        jsonrpc: '2.0',
        method: 'eth_call',
        params: [{
          to: wallets[0].address,
          data: '0x'
        }, 'latest'],
        id: 500 + i
      };
      const response = await bafClient.post('/rpc', req, {
        headers: {
          'X-Forwarded-For': clientIp,
          'X-Real-IP': clientIp
        }
      });
      if (response.data.error) blocked++;
      else allowed++;
      await new Promise(res => setTimeout(res, 20));
    }
    expect(blocked).toBeGreaterThanOrEqual(10); // Al menos la mitad bloqueadas
  }, 20000);

  test('should block repeated requests with same nonce', async () => {
    const wallet = wallets[1];
    const nonce = await provider.getTransactionCount(wallet.address);
    const clientIp = '198.51.100.99';
    let blocked = 0;
    for (let i = 0; i < 10; i++) {
      const tx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[2].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${nonce.toString(16)}`,
          chainId: `0x${chainId.toString(16)}`
        }],
        id: 600 + i
      };
      const response = await bafClient.post('/rpc', tx, {
        headers: {
          'X-Forwarded-For': clientIp,
          'X-Real-IP': clientIp
        }
      });
      if (response.data.error) blocked++;
      await new Promise(res => setTimeout(res, 10));
    }
    expect(blocked).toBeGreaterThanOrEqual(5); // Al menos la mitad bloqueadas
  }, 15000);

  test('should return well-formed error for blocked requests', async () => {
    const wallet = wallets[0];
    const nonce = await provider.getTransactionCount(wallet.address);
    const clientIp = '192.0.2.200';
    // Send enough to trigger block
    let errorObj = null;
    for (let i = 0; i < 15; i++) {
      const tx = {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          from: wallet.address,
          to: wallets[1].address,
          value: '0x1000000000000000',
          gas: '0x5208',
          gasPrice: '0x4A817C800',
          nonce: `0x${(nonce + i).toString(16)}`,
          chainId: `0x${chainId.toString(16)}`
        }],
        id: 700 + i
      };
      const response = await bafClient.post('/rpc', tx, {
        headers: {
          'X-Forwarded-For': clientIp,
          'X-Real-IP': clientIp
        }
      });
      if (response.data.error) {
        errorObj = response.data.error;
        break;
      }
      await new Promise(res => setTimeout(res, 10));
    }
    expect(errorObj).toBeDefined();
    expect(typeof errorObj).toBe('object');
    expect(errorObj.message || '').toMatch(/block|rate|limit|circuit/i);
  }, 15000);

  // New: should respond well to eth_getBalance for a fresh IP
  test('should respond well to eth_getBalance for a fresh IP', async () => {
    const wallet = wallets[0];
    const clientIp = '203.0.113.200';
    const response = await bafClient.post('/rpc', {
      jsonrpc: '2.0',
      method: 'eth_getBalance',
      params: [wallet.address, 'latest'],
      id: 950
    }, {
      headers: {
        'X-Forwarded-For': clientIp,
        'X-Real-IP': clientIp
      }
    });
    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    expect(response.data.result || response.data.error).toBeDefined();
  }, 10000);

  // New: should respond well to net_version for a fresh IP
  test('should respond well to net_version for a fresh IP', async () => {
    const clientIp = '203.0.113.201';
    const response = await bafClient.post('/rpc', {
      jsonrpc: '2.0',
      method: 'net_version',
      params: [],
      id: 951
    }, {
      headers: {
        'X-Forwarded-For': clientIp,
        'X-Real-IP': clientIp
      }
    });
    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    expect(response.data.result || response.data.error).toBeDefined();
  }, 10000);

  afterAll(() => {
    console.log('[CLEANUP] Mempool flooding tests complete');
  });
});
