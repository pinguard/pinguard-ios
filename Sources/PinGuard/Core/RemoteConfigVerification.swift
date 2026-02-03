import CryptoKit
import Foundation
import Security

struct HMACRemoteConfigVerifier: RemoteConfigVerifier {
    private let secretProvider: (String) -> Data?

    init(secretProvider: @escaping (String) -> Data?) {
        self.secretProvider = secretProvider
    }

    func verify(blob: RemoteConfigBlob) -> Bool {
        guard case .hmacSHA256(let secretID) = blob.signatureType else {
            return false
        }

        guard let secret = secretProvider(secretID) else {
            return false
        }

        let key = SymmetricKey(data: secret)
        let computed = HMAC<SHA256>.authenticationCode(for: blob.payload, using: key)
        return Data(computed) == blob.signature
    }
}

struct PublicKeyRemoteConfigVerifier: RemoteConfigVerifier {

    private let keyProvider: (String) -> SecKey?

    init(keyProvider: @escaping (String) -> SecKey?) {
        self.keyProvider = keyProvider
    }

    func verify(blob: RemoteConfigBlob) -> Bool {
        guard case .publicKey(let keyID) = blob.signatureType else {
            return false
        }

        guard let key = keyProvider(keyID) else {
            return false
        }

        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
            return false
        }

        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(key, algorithm, blob.payload as CFData, blob.signature as CFData, &error)
        return result
    }
}
