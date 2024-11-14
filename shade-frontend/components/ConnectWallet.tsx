'use client'

import React from 'react'
import { ConnectButton } from '@rainbow-me/rainbowkit'
import { useAccount } from 'wagmi'
import { useEffect } from 'react'

interface ConnectWalletProps {
  onConnect: () => void
}

export default function ConnectWallet({ onConnect }: ConnectWalletProps) {
  const { isConnected } = useAccount()

  useEffect(() => {
    if (isConnected) {
      onConnect()
    }
  }, [isConnected, onConnect])

  return (
    <div className="space-y-4">
      <ConnectButton.Custom>
        {({
          account,
          chain,
          openAccountModal,
          openChainModal,
          openConnectModal,
          mounted,
        }) => {
          return (
            <div
              {...(!mounted && {
                'aria-hidden': true,
                style: {
                  opacity: 0,
                  pointerEvents: 'none',
                  userSelect: 'none',
                },
              })}
            >
              {(() => {
                if (!mounted || !account || !chain) {
                  return (
                    <button
                      onClick={openConnectModal}
                      className="w-full py-2 px-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                    >
                      Connect Wallet
                    </button>
                  );
                }

                return (
                  <div className="space-y-2">
                    <button
                      onClick={openAccountModal}
                      className="w-full py-2 px-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                    >
                      {account.displayName}
                    </button>
                  </div>
                );
              })()}
            </div>
          );
        }}
      </ConnectButton.Custom>
    </div>
  )
}
