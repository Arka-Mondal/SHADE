'use client'
import React from 'react'

interface AuthStatusProps {
  step: 'connect' | 'register' | 'session'
  did: string | null
  sessionId: string | null
}

export default function AuthStatus({ step, did, sessionId }: AuthStatusProps) {
  return (
    <div className="space-y-2">
      <div className="flex justify-between mb-4">
        <div className={`flex-1 text-center ${step === 'connect' ? 'text-blue-500' : 'text-gray-400'}`}>
          Connect
        </div>
        <div className={`flex-1 text-center ${step === 'register' ? 'text-blue-500' : 'text-gray-400'}`}>
          Register
        </div>
        <div className={`flex-1 text-center ${step === 'session' ? 'text-blue-500' : 'text-gray-400'}`}>
          Session
        </div>
      </div>
      
      {did && (
        <p className="text-sm text-gray-400">
          DID: {did.slice(0, 16)}...{did.slice(-8)}
        </p>
      )}
      
      {sessionId && (
        <p className="text-sm text-gray-400">
          Session: {sessionId.slice(0, 10)}...{sessionId.slice(-8)}
        </p>
      )}
    </div>
  )
}
