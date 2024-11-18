import { createPublicClient, createWalletClient, custom, http} from 'viem';
import { baseSepolia } from 'viem/chains';

export const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: custom(window.ethereum)
})

export const getWalletClient = (account: `0x${string}`) => createWalletClient({
    account,
    chain: baseSepolia,
    transport: custom(window.ethereum)
});