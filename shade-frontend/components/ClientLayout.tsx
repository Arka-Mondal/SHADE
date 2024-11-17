"use client";
import React from 'react';
import { WagmiProvider} from 'wagmi';
import { config } from '../app/config/wagmiConfig';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const ClientLayout = ({children}: {children: React.ReactNode}) => {
    const queryClient = new QueryClient();

  return (
    <div>
        <WagmiProvider config={config}>
            <QueryClientProvider client={queryClient}>
            {children}
            </QueryClientProvider>
        </WagmiProvider>
    </div>
  )
}

export default ClientLayout