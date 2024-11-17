interface PrivateKeyModalProps {
    isOpen: boolean;
    privateKey: string;
    onClose: () => void;
    onConfirm: () => void;
  }
  
  export default function PrivateKeyModal({ isOpen, privateKey, onClose, onConfirm }: PrivateKeyModalProps) {
    if (!isOpen) return null;
  
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-gray-800 p-8 rounded-lg max-w-lg w-full mx-4">
          <h2 className="text-2xl font-bold mb-4 text-white">Save Your Private Key</h2>
          <div className="mb-6">
            <p className="text-gray-300 mb-4">
              Please securely store your private key. You will need this for future authentication.
              Never share this key with anyone!
            </p>
            <div className="bg-gray-900 p-4 rounded-lg mb-4">
              <div className="flex items-center justify-between">
                <code className="text-green-400 break-all">{privateKey}</code>
                <button
                  onClick={() => navigator.clipboard.writeText(privateKey)}
                  className="ml-2 p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
          <div className="flex justify-end gap-4">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600"
            >
              Cancel
            </button>
            <button
              onClick={onConfirm}
              className="px-4 py-2 bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-lg 
                hover:from-purple-700 hover:to-blue-700"
            >
              I Have Saved My Private Key
            </button>
          </div>
        </div>
      </div>
    );
  }