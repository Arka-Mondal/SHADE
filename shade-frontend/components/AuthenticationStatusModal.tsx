interface AuthenticationStatusModalProps {
    status: 'loading' | 'success' | 'failed' | 'none';
    onClose: () => void;
  }
  
  export default function AuthenticationStatusModal({ status, onClose }: AuthenticationStatusModalProps) {
    if (status === 'none') return null;
  
    return (
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
        <div className="bg-gray-800 rounded-full p-8 border border-gray-700 shadow-xl">
          {status === 'loading' && (
            <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-purple-500" />
          )}
          
          {status === 'success' && (
            <div className="text-green-500 animate-scale-in">
              <svg className="h-16 w-16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path 
                  strokeLinecap="round" 
                  strokeLinejoin="round" 
                  strokeWidth={2} 
                  d="M5 13l4 4L19 7" 
                />
              </svg>
            </div>
          )}
          
          {status === 'failed' && (
            <div className="text-red-500 animate-scale-in">
              <svg className="h-16 w-16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path 
                  strokeLinecap="round" 
                  strokeLinejoin="round" 
                  strokeWidth={2} 
                  d="M6 18L18 6M6 6l12 12" 
                />
              </svg>
            </div>
          )}
        </div>
      </div>
    );
  }