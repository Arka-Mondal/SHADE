import { getDefaultConfig } from '@rainbow-me/rainbowkit'
import { sepolia } from 'viem/chains'
import { QueryClient } from '@tanstack/react-query'

const projectId = '197b368375c6165f1d98c386f784b6f1'

export const config = getDefaultConfig({
  appName: 'SHADE Protocol',
  projectId,
  chains: [sepolia],
  ssr: true
})

export const queryClient = new QueryClient()
