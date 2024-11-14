'use client'
import React from 'react'

interface DIDRegistrationProps {
  onRegister: (did: string) => void
}

export default function DIDRegistration({ onRegister }: DIDRegistrationProps) {
  const handleRegister = async () => {
    // TODO: Implement actual DID registration
    const mockDid = `did:eth:${Date.now()}`
    onRegister(mockDid)
  }

  return (
    <div className="space-y-4">
      <button
        onClick={handleRegister}
        className="w-full py-2 px-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
      >
        Register DID
      </button>
    </div>
  )
}
