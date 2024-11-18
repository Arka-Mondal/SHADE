"use client";
import { usePrivy } from "@privy-io/react-auth";
import IdentityRegistry from '../IdentityRegistry/IdentityRegistry.json';
import { generateKeyPair, deriveSharedSecret, deriveKey, decrypt, jsondec, jsonBitArrEncode, jsonBitArrDecode, sign, verify } from "@/utils/utils";
import { publicClient, getWalletClient } from "@/app/config/viemConfig";
import { useState, useEffect } from 'react';
import Notification from '../components/Notification';
import PrivateKeyModal from '../components/PrivateKeyModal';

export default function Home() {
  const { login, ready, user, logout } = usePrivy();
  const [notification, setNotification] = useState<{
    message: string;
    type: 'success' | 'error' | 'warning' | 'info';
  } | null>(null);
  const [isRegistering, setIsRegistering] = useState(false);
  const [didDocument, setDidDocument] = useState<{
    did: string;
    publicKey: string;
    timestamp: bigint;
    active: boolean;
  } | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [showPrivateKeyModal, setShowPrivateKeyModal] = useState(false);
  const [generatedKeyPair, setGeneratedKeyPair] = useState<{ privateKey: string; publicKey: string } | null>(null);

  useEffect(() => {
    if (user?.wallet?.address) {
      fetchDIDDocument();
    }
  }, [user?.wallet?.address]);

  const fetchDIDDocument = async () => {
    if (!user?.wallet?.address) return;
    
    setIsLoading(true);
    try {
      const contractAddress = IdentityRegistry.address.startsWith('0x') 
        ? IdentityRegistry.address as `0x${string}`
        : `0x${IdentityRegistry.address}` as `0x${string}`;

      console.log('Contract Address:', contractAddress);
      console.log('User Address:', user.wallet.address);

      const result = await publicClient.readContract({
        address: contractAddress,
        abi: IdentityRegistry.abi,
        functionName: 'getIdentity',
        args: [user.wallet.address]
      }) as { did: string; publicKey: string; timestamp: bigint; active: boolean };

      console.log('Fetched DID Document:', result);
      setDidDocument(result);
    } catch (error) {
      console.error('Error fetching DID document:', error);
      setDidDocument(null);
    } finally {
      setIsLoading(false);
    }
  };

  const registerDID = async () => {
    if (isRegistering) return;
    setIsRegistering(true);
    
    try {
      let keyPair;
      
      if (didDocument?.active) {
        const privateKey = prompt("Please enter your private key for this DID:");
        if (!privateKey) {
          setNotification({
            message: 'Private key is required to proceed',
            type: 'error'
          });
          return;
        }
        
        keyPair = { privateKey, publicKey: didDocument.publicKey };
        await proceedWithRegistration(keyPair);
      } else {
        keyPair = await generateKeyPair();
        setGeneratedKeyPair(keyPair);
        setShowPrivateKeyModal(true);
      }
    } catch (error) {
      console.error('DID registration error:', error);
      setNotification({
        message: `Failed to register DID: ${error instanceof Error ? error.message : 'Unknown error'}`,
        type: 'error'
      });
    } finally {
      setIsRegistering(false);
    }
  };

  const proceedWithRegistration = async (keyPair: { privateKey: string; publicKey: string }) => {
    try {
      if (!user?.wallet?.address) {
        setNotification({
          message: 'Please connect your wallet first to register DID',
          type: 'error'
        });
        return;
      }

      localStorage.setItem('privateKey', keyPair.privateKey);
      localStorage.setItem('publicKey', keyPair.publicKey);

      const timestamp = Date.now();
      const uniqueIdentifier = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(`${user.wallet.address}${timestamp}`)
      );
      const hexIdentifier = Array.from(new Uint8Array(uniqueIdentifier))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      const did = `did:shade:${hexIdentifier}`;

      const contractAddress = IdentityRegistry.address.startsWith('0x') 
        ? IdentityRegistry.address as `0x${string}`
        : `0x${IdentityRegistry.address}` as `0x${string}`;

      console.log('Contract Address:', contractAddress);

      const walletClientWithAccount = getWalletClient(user.wallet.address as `0x${string}`);
      const contractParams = {
        address: contractAddress,
        abi: IdentityRegistry.abi,
        functionName: 'registerDID',
        args: [did, keyPair.publicKey]
      } as const;

      await publicClient.simulateContract({
        ...contractParams,
        account: user.wallet.address as `0x${string}`
      });
      
      const hash = await walletClientWithAccount.writeContract(contractParams);
      
      const receipt = await publicClient.waitForTransactionReceipt({ hash });

      if (receipt.status === 'success') {
        setNotification({
          message: 'DID registered successfully!',
          type: 'success'
        });

        setTimeout(async () => {
          await fetchDIDDocument();
        }, 2000);
      } else {
        throw new Error('Transaction failed');
      }
    } catch (error) {
      console.error('DID registration error:', error);
      setNotification({
        message: `Failed to register DID: ${error instanceof Error ? error.message : 'Unknown error'}`,
        type: 'error'
      });
    }
  };

  const handlePrivateKeyConfirm = async () => {
    if (generatedKeyPair) {
      setShowPrivateKeyModal(false);
      await proceedWithRegistration(generatedKeyPair);
      setGeneratedKeyPair(null);
    }
  };

  const handleLogout = () => {
    setDidDocument(null);
    setNotification(null);
    setIsRegistering(false);
    setIsLoading(false);
    setShowPrivateKeyModal(false);
    setGeneratedKeyPair(null);
    
    localStorage.removeItem('privateKey');
    localStorage.removeItem('publicKey');
    
    logout();
  };

  const handleAuthentication = async () => {
    if (!user?.wallet?.address) {
      setNotification({
        message: 'Please connect your wallet first to authenticate',
        type: 'error'
      });
      return;
    }

    const privateKeyFromUser = prompt("Please enter your private key for this DID:");

    const ephemeralKeyPair = await generateKeyPair();

    const concat = didDocument?.did + ephemeralKeyPair.publicKey;
    const concatHashOfDIDAndEphemeralPublicKey = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(concat));
    const hexConcatHashOfDIDAndEphemeralPublicKey = Array.from(new Uint8Array(concatHashOfDIDAndEphemeralPublicKey))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
      
    const res = await fetch("http://localhost:8080/shade/v1/authenticate", {
      method: "POST",
      body: JSON.stringify({
        ephemeralPublicKey: ephemeralKeyPair.publicKey,
        did: didDocument?.did,
        hash: hexConcatHashOfDIDAndEphemeralPublicKey,
      }),
    })

    const data = await res.json();
    console.log(data);

    const contractAddress = IdentityRegistry.address.startsWith('0x') 
        ? IdentityRegistry.address as `0x${string}`
        : `0x${IdentityRegistry.address}` as `0x${string}`;

    const result = await publicClient.readContract({
      address: contractAddress,
      abi: IdentityRegistry.abi,
      functionName: 'getDIDDocument',
      args: [data.did]
    }) as { did: string; publicKey: string; timestamp: bigint; active: boolean };

    console.log('Fetched Server"s DID Document:', result);

    const serverIdentityPubliceKey = Buffer.from(result.publicKey);

    const serverEphemeralPublicKey = Buffer.from(data.ephemeral_public_key);

    console.log("server public key", serverIdentityPubliceKey.toString())


    let sharedSecretIdentity;
    if (privateKeyFromUser) {
      console.log(privateKeyFromUser)
        sharedSecretIdentity = await deriveSharedSecret(privateKeyFromUser, serverIdentityPubliceKey.toString());
        // sharedSecretIdentity = await deriveSharedSecret(Buffer.from(privateKeyFromUser), serverIdentityPubliceKey);
    } else {
        alert("null")
    }
    

    const serverEphemeralPublicKey_PEM = jsondec(serverEphemeralPublicKey.toString())

    const sharedSecretEphemeralKey = await deriveSharedSecret(ephemeralKeyPair.privateKey, serverEphemeralPublicKey_PEM);
    // const sharedSecretEphemeralKey = await deriveSharedSecret(Buffer.from(ephemeralKeyPair.privateKey), serverEphemeralPublicKey);

    console.log('Shared Secret Identity:', sharedSecretIdentity);
    console.log('Shared Secret Eph:', sharedSecretEphemeralKey);
    console.log('Data Salt:', data.salt)
    console.log('Data Salt:', Buffer.from(jsonBitArrDecode(data.salt)));
    console.log('Encrypted Challenge:', Buffer.from(jsonBitArrDecode(data.encrypted_challenge)));

    const derivedKeyResponse = await deriveKey(Buffer.from(sharedSecretIdentity!), Buffer.from(sharedSecretEphemeralKey), Buffer.from(jsonBitArrDecode(data.salt)));

    console.log('Derived Key Response:', derivedKeyResponse);

    const challenge = await decrypt(derivedKeyResponse.key, Buffer.from(jsonBitArrDecode(data.encrypted_challenge)));

    console.log('Challenge Result:', challenge);

    const signature = await sign(privateKeyFromUser!, challenge.toString());

    console.log("Signature", signature);
    console.log("Signature Length: ", signature.length);

    console.log("Verify: ", await verify(didDocument?.publicKey!, challenge.toString(), signature));

    console.log("Challenge2: ", challenge);

    console.log("my public key: ", didDocument?.publicKey)

    const response = await fetch('http://localhost:8080/shade/v1/verify', {
      method: "POST",
      body: JSON.stringify({
        session_id: data.session_id,
        did: didDocument?.did,
        signature: jsonBitArrEncode(signature),
        challenge: jsonBitArrEncode(challenge),
      })
    })

    const verifiedData = await response.json();
    console.log(verifiedData.status);

  }

  return (
    <main className="min-h-screen bg-gradient-to-b from-gray-900 to-gray-800 text-white">
      {generatedKeyPair && (
        <PrivateKeyModal
          isOpen={showPrivateKeyModal}
          privateKey={generatedKeyPair.privateKey}
          onClose={() => {
            setShowPrivateKeyModal(false);
            setGeneratedKeyPair(null);
          }}
          onConfirm={handlePrivateKeyConfirm}
        />
      )}

      {user && (
        <div className="absolute top-4 right-4">
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg 
              border border-gray-700 transition-all duration-200 group"
          >
            <span className="text-gray-300 group-hover:text-white">Logout</span>
            <svg 
              xmlns="http://www.w3.org/2000/svg" 
              className="h-5 w-5 text-gray-300 group-hover:text-white" 
              fill="none" 
              viewBox="0 0 24 24" 
              stroke="currentColor"
            >
              <path 
                strokeLinecap="round" 
                strokeLinejoin="round" 
                strokeWidth={2} 
                d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" 
              />
            </svg>
          </button>
        </div>
      )}
      
      {notification && (
        <Notification
          message={notification.message}
          type={notification.type}
          onClose={() => setNotification(null)}
        />
      )}
      <div className="container mx-auto px-4 py-12">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4">
            SHADE Authentication Protocol
          </h1>
          <p className="text-xl text-gray-300 mb-8">
            Secure, Decentralized Identity Authentication
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-8 mt-16">
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-xl font-bold mb-2">1. Wallet Connection</h3>
            <p className="text-gray-300 mb-4">
              Connect your Web3 wallet to begin the authentication process
            </p>
            <button
              onClick={login}
              disabled={!ready}
              className="w-full bg-gradient-to-r from-purple-600 to-blue-600 text-white font-semibold py-3 px-8 rounded-lg 
              hover:from-purple-700 hover:to-blue-700 transition-all duration-200 transform hover:scale-105
              disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
            >
              {user?.wallet?.address ? `${user?.wallet?.address.slice(0, 4)}...${user?.wallet?.address.slice(-4)}` : "Connect Wallet"}
            </button>
          </div>
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-xl font-bold mb-2">2. DID Registration</h3>
            <p className="text-gray-300 mb-4">
              {!user?.wallet?.address 
                ? "Connect your wallet first to register DID"
                : didDocument 
                  ? `DID: ${didDocument.did.slice(0, 15)}...${didDocument.did.slice(-4)}`
                  : "Register your decentralized identity with cryptographic proof"
              }
            </p>
            {didDocument && (
              <div className="text-sm text-gray-400 mb-4">
                <div className="flex items-center justify-between mb-2">
                  <p>DID: {didDocument.did}</p>
                  <button
                    onClick={() => navigator.clipboard.writeText(didDocument.did)}
                    className="ml-2 p-1 text-gray-400 hover:text-white"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                  </button>
                </div>
                <div className="flex items-center justify-between">
                  <p>Public Key: {didDocument.publicKey.replace(/^-----BEGIN PUBLIC KEY-----\n|\n-----END PUBLIC KEY-----$/g, '').slice(0, 10)}...{didDocument.publicKey.replace(/^-----BEGIN PUBLIC KEY-----\n|\n-----END PUBLIC KEY-----$/g, '').slice(-10)}</p>
                  <button
                    onClick={() => navigator.clipboard.writeText(didDocument.publicKey)}
                    className="ml-2 p-1 text-gray-400 hover:text-white"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                  </button>
                </div>
                <p>Status: {didDocument.active ? 'Active' : 'Inactive'}</p>
                <p>Registered: {new Date(Number(didDocument.timestamp) * 1000).toLocaleDateString()}</p>
              </div>
            )}
            <button
              disabled={!user?.wallet?.address || isRegistering || didDocument?.active || isLoading}
              className="w-full bg-gradient-to-r from-purple-600 to-blue-600 text-white font-semibold py-3 px-8 rounded-lg 
              hover:from-purple-700 hover:to-blue-700 transition-all duration-200 transform hover:scale-105
              disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
              onClick={registerDID}
            >
              {!user?.wallet?.address 
                ? "Connect Wallet First"
                : isRegistering 
                  ? "Registering..." 
                  : isLoading
                    ? "Loading..."
                    : didDocument?.active 
                      ? "DID Registered" 
                      : "Register DID"
              }
            </button>
          </div>
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-xl font-bold mb-2">3. Initiate Authentication</h3>
            <p className="text-gray-300 mb-4">
              Authenticate with your Digital Identity (DIDs)
            </p>
            <button
              disabled={!user?.wallet?.address}
              className="w-full bg-gradient-to-r from-purple-600 to-blue-600 text-white font-semibold py-3 px-8 rounded-lg 
              hover:from-purple-700 hover:to-blue-700 transition-all duration-200 transform hover:scale-105
              disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
              onClick={handleAuthentication}
            >
              Authenticate
            </button>
          </div>
        </div>
      </div>
    </main>
  );
}