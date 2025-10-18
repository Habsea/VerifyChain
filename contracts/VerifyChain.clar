;; VerifyChain - Decentralized credential verification and validation network
(define-data-var credential-issuer principal tx-sender)
(define-data-var total-verified-credentials uint u0)
(define-data-var verification-threshold uint u75) ;; percentage required for validation
(define-data-var last-verification-round uint u0)

(define-map credential-records principal uint)
(define-map credential-types principal (string-utf8 64))
(define-map approved-credential-types (string-utf8 64) bool)

;; Error codes
(define-constant err-unauthorized-issuer (err u8100))
(define-constant err-issuer-already-registered (err u8101))
(define-constant err-invalid-credential-count (err u8102))
(define-constant err-insufficient-verification-votes (err u8103))
(define-constant err-no-credentials-to-claim (err u8104))
(define-constant err-invalid-credential-type (err u8105))
(define-constant err-credential-type-not-approved (err u8106))

;; Verify credential issuer authorization
(define-private (is-credential-issuer (caller principal))
  (begin
    (asserts! (is-eq caller (var-get credential-issuer)) err-unauthorized-issuer)
    (ok true)))

;; Initialize credential verification network
(define-public (register-issuer-network (issuer principal))
  (begin
    (asserts! (is-none (map-get? credential-records issuer)) err-issuer-already-registered)
    (var-set credential-issuer issuer)
    (ok "VerifyChain credential network initialized")))

;; Approve credential type for issuance
(define-public (approve-credential-type (cred-type (string-utf8 64)))
  (begin
    (try! (is-credential-issuer tx-sender))
    (asserts! (> (len cred-type) u0) err-invalid-credential-type)
    (map-set approved-credential-types cred-type true)
    (ok "Credential type approved for network")))

;; Issue verified credential
(define-public (issue-verified-credential (credential-count uint) (cred-type (string-utf8 64)))
  (begin
    (asserts! (> credential-count u0) err-invalid-credential-count)
    (asserts! (default-to false (map-get? approved-credential-types cred-type)) err-credential-type-not-approved)
    
    (let ((current-credentials (default-to u0 (map-get? credential-records tx-sender))))
      (map-set credential-records tx-sender (+ current-credentials credential-count))
      (map-set credential-types tx-sender cred-type)
      (var-set total-verified-credentials (+ (var-get total-verified-credentials) credential-count))
      (ok (+ current-credentials credential-count)))))

;; Execute verification round
(define-public (execute-verification-round)
  (begin
    (try! (is-credential-issuer tx-sender))
    (let ((current-round (+ (var-get last-verification-round) u1))
          (total-creds (var-get total-verified-credentials)))
      (asserts! (> total-creds (var-get last-verification-round)) err-insufficient-verification-votes)
      
      (let ((verification-reward-pool (* (var-get verification-threshold) total-creds)))
        (var-set last-verification-round current-round)
        (ok verification-reward-pool)))))

;; Claim verified credential rewards
(define-public (claim-credential-rewards)
  (begin
    (let ((issued-credentials (default-to u0 (map-get? credential-records tx-sender))))
      (asserts! (> issued-credentials u0) err-no-credentials-to-claim)
      
      (let ((total-credentials (var-get total-verified-credentials))
            (base-verification-rewards (* (var-get verification-threshold) issued-credentials))
            (credential-ratio (/ (* issued-credentials u100000) total-credentials)))
        
        (let ((final-verification-rewards (/ (* credential-ratio base-verification-rewards) u100000)))
          (map-delete credential-records tx-sender)
          (map-delete credential-types tx-sender)
          (var-set total-verified-credentials (- (var-get total-verified-credentials) issued-credentials))
          (ok (+ issued-credentials final-verification-rewards)))))))

;; Read-only functions
(define-read-only (get-issued-credentials (holder principal))
  (default-to u0 (map-get? credential-records holder)))

(define-read-only (get-credential-type (holder principal))
  (map-get? credential-types holder))

(define-read-only (get-total-verified-credentials)
  (var-get total-verified-credentials))

(define-read-only (is-credential-type-approved (cred-type (string-utf8 64)))
  (default-to false (map-get? approved-credential-types cred-type)))