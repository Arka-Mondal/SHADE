'use client'

import React from 'react'
    
interface SessionManagerProps {
  did: string
  onSessionCreated: (sessionId: string) => void
}

export default function SessionManager({ did, onSessionCreated }: SessionManagerProps) {
  const createSession = async () => {
    // TODO: Implement actual session creation
    const mockSessionId = `session_${Date.now()}`
    onSessionCreated(mockSessionId)
  }

  return (
    <div className="space-y-4">
      <button
        onClick={createSession}
        className="w-full py-2 px-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
      >
        Create Session
      </button>
    </div>
  )
}
