Digital Signature Service (DSS)
================================

Overview
--------
The Digital Signature Service (DSS) is a trusted third-party system that manages 
cryptographic keys and digital signatures on behalf of an organization's employees.  

It follows a PKI (Public Key Infrastructure) architecture, where a Certificate Authority (CA) 
issues and revokes certificates, and the DSS securely manages employees' private keys.

Employees never directly hold their private keys. Instead, the DSS generates, stores 
(encrypted), and uses them to sign documents when requested. Clients can request other users’ 
certificates to verify signatures.

--------------------------------

Architecture
------------
Client
  - Authenticates with DSS.
  - Requests creation/deletion of certificates.
  - Requests DSS to sign documents.
  - Requests other users’ certificates for signature verification.
  - Stores only the DSS certificate (public) locally for channel validation.

DSS (Digital Signature Service)
  - Generates public/private key pairs for users.
  - Encrypts and stores private keys securely in the DB.
  - Creates Certificate Signing Requests (CSR).
  - Sends CSR to the CA and stores the returned certificate.
  - Signs documents on behalf of users with their private key.
  - Forwards revocation requests to the CA when a user is deleted.
  - Provides certificates to clients for verification.

CA (Certificate Authority)
  - Receives CSRs from DSS, signs them, and returns certificates.
  - Manages the certificate database (issued, expired, revoked).
  - Publishes a Certificate Revocation List (CRL).
  - Handles revocation requests from DSS.

--------------------------------

Database Structure
------------------
DSS DB Tables
  - users (id, username, password_hash, first_login, is_admin)
  - keys (user_id, cert_pem, private_key, created_at)

CA DB Tables
  - certificates (serial, user_id, certificate_pem, issued_at, expires_at, revoked_at)

--------------------------------

Workflows
---------
1. Offline Registration
  - Client ( by admin ) -> DSS: REGISTER_USER (username)
  - DSS generate random password 
  - DSS store user into DB (first_login = 0)
  - DSS "sends" offline its certificate
  - DSS -> Client: USER_REGISTERED

2. First Login
  - Client -> DSS: FIRST_LOGIN (username, tempPassword, newPassword)
  - DSS: check flag and tempPassword
  - DSS: hash newPassword and store user (first_login = 1)
  - DSS -> Client: AUTH_OK

3. Normal Login
  - Client -> DSS: AUTH (username, password)
  - DSS: check username and password
  - DSS: get user certificate and userId
  - DSS -> CA: CHECK_CERT (userId)
  - CA -> DSS: CERT_VALID
  - DSS -> Client: AUTH_OK
  - If not valid ( like expired or revoked delete key pairs?)

4. Certificate Creation
   - Client -> DSS: REQ_CERT (username)
   - DSS generates keypair (pub/priv)
   - DSS encrypts private key with user metadata
   - DSS creates CSR
   - DSS -> CA: Send CSR (REQ_CERT userId csr)
   - CA -> DSS: Return certificate
   - DSS stores certificate and priv key in DB
   - DSS -> Client: Response

5. Document Signing
   - Client -> DSS: SIGN_DOC (document path)
   - DSS retrieves encrypted private key 
   - DSS decrypts private key
   - DSS signs document
   - DSS -> Client: SIGN_OK

6. Certificate Revocation / User Deletion
   - Client -> DSS: DEL_KEYS (username)
   - DSS -> CA: REVOKE_CERT (userId, serial)
   - CA marks certificate as revoked
   - CA -> DSS: REVOKE_OK
   - DSS deletes keys and user from DB
   - DSS -> Client: DEL_OK

7. Get Certificate
   - Client -> DSS: GET_CERT (username)
   - DSS looks up certificate in DB
   - DSS -> CA: CHECK_CERT ( userId )
   - CA -> DSS: CERT_VALID
   - DSS -> Client: Return certificate PEM
   - Client uses certificate to verify signatures and extrac pubKey

--------------------------------

Security Considerations
-----------------------
- Private keys never leave DSS and are stored AES-encrypted.
- Clients hold only the CA root for validation.
- DSS ensures revocation is always forwarded to CA.
- CA maintains a CRL (Certificate Revocation List) so relying parties can 
  detect revoked certificates.

--------------------------------
