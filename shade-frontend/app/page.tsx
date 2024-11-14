'use client'

import { useState } from 'react'
import Image from 'next/image'
import ConnectWallet from '@/components/ConnectWallet'
import DIDRegistration from '@/components/DIDRegistration'
import SessionManager from '@/components/SessionManager'
import AuthStatus from '@/components/AuthStatus'

export default function Home() {
  const [step, setStep] = useState<'connect' | 'register' | 'session'>('connect')
  const [did, setDid] = useState<string | null>(null)
  const [sessionId, setSessionId] = useState<string | null>(null)

  return (
    <main className="min-h-screen bg-gradient-to-b from-gray-900 to-gray-800 text-white">
      {/* Hero Section */}
      <div className="container mx-auto px-4 py-12">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4">SHADE Authentication Protocol</h1>
          <p className="text-xl text-gray-300">
            Secure, Decentralized Identity Authentication
          </p>
        </div>

        {/* Authentication Flow */}
        <div className="max-w-md mx-auto bg-gray-800 p-6 rounded-lg shadow-xl">
          <div className="mb-8">
            <AuthStatus step={step} did={did} sessionId={sessionId} />
          </div>

          {step === 'connect' && (
            <ConnectWallet onConnect={() => setStep('register')} />
          )}

          {step === 'register' && (
            <DIDRegistration
              onRegister={(newDid) => {
                setDid(newDid)
                setStep('session')
              }}
            />
          )}

          {step === 'session' && did && (
            <SessionManager
              did={did}
              onSessionCreated={(newSessionId) => {
                setSessionId(newSessionId)
              }}
            />
          )}
        </div>

        {/* Protocol Steps */}
        <div className="grid md:grid-cols-3 gap-8 mt-16">
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-xl font-bold mb-2">1. Wallet Connection</h3>
            <p className="text-gray-300">Connect your Web3 wallet to begin the authentication process</p>
          </div>
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-xl font-bold mb-2">2. DID Registration</h3>
            <p className="text-gray-300">Register your decentralized identity with cryptographic proof</p>
          </div>
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-xl font-bold mb-2">3. Session Management</h3>
            <p className="text-gray-300">Secure session creation with blockchain-based verification</p>
          </div>
        </div>
      </div>
    </main>
  )
}
