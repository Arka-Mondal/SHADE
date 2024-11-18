interface PrivateKeyInputModalProps {
    isOpen: boolean;
    onClose: () => void;
    onSubmit: (privateKey: string) => void;
  }
  
  export default function PrivateKeyInputModal({ isOpen, onClose, onSubmit }: PrivateKeyInputModalProps) {
    const handleSubmit = (e: React.FormEvent) => {
      e.preventDefault();
      const formData = new FormData(e.target as HTMLFormElement);
      const privateKey = formData.get('privateKey') as string;
      onSubmit(privateKey);
    };
  
    if (!isOpen) return null;
  
    return (
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
        <div className="bg-gray-800 rounded-xl p-6 w-full max-w-md border border-gray-700 shadow-xl">
          <h3 className="text-xl font-bold mb-4 text-gray-100">Enter Private Key</h3>
          <form onSubmit={handleSubmit}>
            <div className="mb-4">
              <label htmlFor="privateKey" className="block text-sm font-medium text-gray-300 mb-2">
                Private Key
              </label>
              <input
                type="password"
                id="privateKey"
                name="privateKey"
                required
                className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-gray-100 
                  focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                placeholder="Enter your private key"
              />
            </div>
            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 bg-gradient-to-r from-purple-600 to-blue-600 
                  hover:from-purple-700 hover:to-blue-700 text-white rounded-lg transition-all duration-200"
              >
                Submit
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  }