interface DIDInfoModalProps {
    isOpen: boolean;
    onClose: () => void;
    didInfo: {
      did: string;
      publicKey: string;
      timestamp: bigint;
      active: boolean;
    } | null;
}

export default function DIDInfoModal({ isOpen, onClose, didInfo }: DIDInfoModalProps) {
    if (!isOpen || !didInfo) return null;

    const handleCopy = (text: string) => {
        navigator.clipboard.writeText(text);
        // You might want to add a toast notification here instead of alert
    };

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
            <div className="bg-gray-800 rounded-xl p-6 w-full max-w-2xl border border-gray-700 shadow-xl">
                <h3 className="text-xl font-bold mb-6 text-gray-100">DID Information</h3>
                <div className="space-y-4 mb-6">
                    {/* DID Section */}
                    <div className="bg-gray-900/50 rounded-lg p-4">
                        <div className="flex justify-between items-start">
                            <span className="text-gray-400 font-semibold w-24">DID:</span>
                            <div className="flex-1 ml-4">
                                <div className="flex items-center justify-between">
                                    <span className="text-gray-300 break-all font-mono text-sm">
                                        {didInfo.did}
                                    </span>
                                    <button 
                                        onClick={() => handleCopy(didInfo.did)}
                                        className="ml-2 p-2 text-gray-400 hover:text-blue-400 transition-colors"
                                    >
                                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                        </svg>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Public Key Section */}
                    <div className="bg-gray-900/50 rounded-lg p-4">
                        <div className="flex justify-between items-start">
                            <span className="text-gray-400 font-semibold w-24">Public Key:</span>
                            <div className="flex-1 ml-4">
                                <div className="flex items-center justify-between">
                                    <span className="text-gray-300 break-all font-mono text-sm">
                                        {didInfo.publicKey}
                                    </span>
                                    <button 
                                        onClick={() => handleCopy(didInfo.publicKey)}
                                        className="ml-2 p-2 text-gray-400 hover:text-blue-400 transition-colors"
                                    >
                                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                        </svg>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Status and Registration Section */}
                    <div className="bg-gray-900/50 rounded-lg p-4">
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <span className="text-gray-400 font-semibold">Status:</span>
                                <span className={`ml-2 ${didInfo.active ? 'text-green-400' : 'text-red-400'}`}>
                                    {didInfo.active ? 'Active' : 'Inactive'}
                                </span>
                            </div>
                            <div>
                                <span className="text-gray-400 font-semibold">Registered:</span>
                                <span className="ml-2 text-gray-300">
                                    {new Date(Number(didInfo.timestamp) * 1000).toLocaleDateString()}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="flex justify-end">
                    <button
                        onClick={onClose}
                        className="px-6 py-2 bg-gradient-to-r from-purple-600 to-blue-600 
                            text-white rounded-lg transition-all duration-200 
                            hover:from-purple-700 hover:to-blue-700 font-semibold"
                    >
                        Close
                    </button>
                </div>
            </div>
        </div>
    );
}