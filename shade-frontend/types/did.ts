export interface DIDDocument {
  did: string
  publicKey: `0x${string}`
  timestamp: number
  active: boolean
}

export interface DIDRegistrationProps {
  onRegister: (did: string) => void
}
