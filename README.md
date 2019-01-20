<h1>OAuth 2.0, OpenIdConnect, SAML Fundamentals</h1>

*   **Basic Authentication** – This is the simplest way to secure your RESTful Web Service. When using this option, the browser presents a challenge popup when you are accessing a secured URI, the username/password combination which will then be base64 encoded and stored in the request header. This encoded string will be checked with each request and verified against the username/password stored on the server.

            **Challenge** :   WWW-Authenticate: Basic realm="digitalconsulting"    
            **Example** : Header   Authorization: Basic ZGVtbzpwQDU1dzByZA=_=  
            (**_Authorization_**: Basic **Base64**($USER : $_**PASSWORD**)  )

*   **Digest Authentication** – Digest Authentication is better than Basic Authentication, as it does not send username and password over the network. Instead it transmits a one-way cryptography hash of the password and additional data. The caveat, however, is that the authenticating server requires an unencrypted password be made available to it so that it can calculate the one-way cryptographic digest used in the validation process.

*   **Cookie Authentication** - Cookie authentication uses [HTTP cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies) to authenticate client requests and maintain session information. It works as follows:
    1.  The client sends a login request to the server.
    2.  On the successful login, the server response includes the [Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) header that contains the cookie name, value, expiry time and some other info. Here is an example that sets the cookie named JSESSIONID:
        1.  Set-Cookie: JSESSIONID=abcde12345; Path=/; **HttpOnly**
    3.  The client needs to send this cookie in the Cookie header in all subsequent requests to the server.
        1.  Cookie: JSESSIONID=abcde12345
    4.  On the logout operation, the server sends back the Set-Cookie header that causes the cookie to expire.**Note:** Cookie authentication is vulnerable to Cross-Site Request Forgeries (CSRF) attacks, so it should be used together with other security measures, such as [CSRF tokens](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Prevention).    

*   **Kerberos**  
           Kerberos is a [computer network](https://en.wikipedia.org/wiki/Computer_network) [authentication](https://en.wikipedia.org/wiki/Authentication) [protocol](https://en.wikipedia.org/wiki/Cryptographic_protocol) that works on the basis of _tickets_ to allow [nodes](https://en.wikipedia.org/wiki/Node_(networking)) communicating over a non-secure network to prove their identity to one another in a secure manner.  
           Kerberos is composed of three parts: a client, a server, and a trusted third party known as the Kerberos **Key Distribution Center (KDC)**. The KDC provides authentication and ticket granting services. The KDC maintains a database or repository of user accounts for all of the security principals in its realm.  
           Many Kerberos distributions use file-based repositories for the Kerberos principal and policy DB and others use Lightweight Directory Access Protocol (LDAP) as the repository.      

*   **GSSAPI / SPNEGO Authentication**   
           SPNEGO is a standard specification that is defined in [The Simple and Protected GSS-API Negotiation Mechanism (IETF RFC 2478)](https://www.ietf.org/rfc/rfc2478.txt).   The authentication of  HTTP requests is triggered by the user (the client-side), which generates an **SPNEGO** token. The Application Server receives this token and decodes and retrieves the user identity from it. The identity is then used to make authorization decisions  
           SPNEGO is an **authentication** technology that is primarily used to provide transparent **CAS (  Central **Authentication** Service  )** authentication to browsers running on Windows running under Active Directory domain credentials. There are three actors involved: the client, the server and the Active Directory Domain Controller/KDC.  

         1\. Client  requests a resource from Server  :                                      HTTP GET  protected page  
         2\. Server, running the SPNEGO Token Handler code  responds:       HTTP 401 - Access Denied WWW-Authenticate: Negotiate  
         3\. Client(Browser) sends ticket request:                                             Kerberos(KRB_TGS_REQ) Requesting ticket from  Key Distribution Center (**KDC**)    
         4\. Kerberos KDC responds:                                                                 Kerberos(KRB_TGS_REP)   necessary Kerberos Ticket wrapped in a SPNEGO Token.    
         5\. Client re-sends the request + the Negotiate SPNEGO Token :       HTTP GET Authorization: Negotiate w/SPNEGO Token  
         6\. Server's SPNEGO Token Handler accepts and responds  :               HTTP 200 - OK WWW-Authenticate w/SPNEGO response + requested page**.**

**Links :**
        [https://www.ibm.com/support/knowledgecenter/en/SSEQTP_liberty/com.ibm.websphere.wlp.doc/ae/cwlp_spnego.html  
](https://www.ibm.com/support/knowledgecenter/en/SSEQTP_liberty/com.ibm.websphere.wlp.doc/ae/cwlp_spnego.html)[https://www.oracle.com/technetwork/articles/idm/weblogic-sso-kerberos-1619890.html](https://www.oracle.com/technetwork/articles/idm/weblogic-sso-kerberos-1619890.html)  
             
               **Note:**  **Kerberos** is a network authentication protocol for client/server applications and **SPNEGO** provides a mechanism for extending Kerberos to Web applications through the standard **HTTP** protocol    

*   **LDAP**  - The **Lightweight Directory Access Protocol (LDAP)** is an application protocol, used for accessing and maintaining distributed directory information services over an Internet Protocol (IP) network.The function of LDAP is to enable access to an existing directory, like Active Directory.  

*   **SecurityContext** – stores the security information related to the HTTP request being processed. By using SecurityContext you would be able to access authentication type used to secure the resource, whether a user belongs to a certain role and whether the request was made over a secure channel.

            [org.springframework.security.core.context.](http://)**SecurityContext**  

            [javax.ws.rs.core.](https://docs.oracle.com/javaee/7/api/javax/ws/rs/core/SecurityContext.html)**SecurityContext**    

            [io.undertow.security.api.](http://undertow.io/javadoc/2.0.x/io/undertow/security/api/SecurityContext.html)**SecurityContext**

*   **SSO / Federated Identity**  
           Before diving into federated authentication, we need to understand what authentication really means. Authentication defines the way a user is identified and validated through some sort of credentials as part of a login flow. Most applications will present a login page to an end user, allowing him to specify a username and a password.  
           Most applications will have a user store (DB or LDAP) containing, among other things, user profile information and credentials. During login, the credentials are validated against this backend user store. The advantage of this approach is that it is simple, because everything is managed within the application, providing a single and consistent way to authenticate an end user. However, if a user needs to access multiple applications where each app requires a different set of credentials, it becomes a hassle for the end user. First, the user will need to remember different passwords – in addition to any other corporate password (eg. AD password) that may already exist. The user is now forced to maintain separate usernames and passwords, dealing with different password policies and expirations. Second, this also creates a headache for administrators  when application users continue to have access to applications that should have been revoked.    

*   **SSO** allows a **single authentication** credential- user ID and password, smart card, one-time password token or a biometric device--to access multiple or **different** systems within a **single** organization. A **federated identity** management system provides **single** access to multiple systems across **different** enterprises.    

*   **OAuth 2** – OAuth is an open standard for authorization   specified in the [OAuth 2.0 Authorization Framework](http://tools.ietf.org/html/rfc6749)  . The purpose of OAUTH is to allow access to some resource by third parties without having to share client username/password (credentials). This access can then be selectively granted and revoked by the client at any time. It establishes a trust relationship between the client and the third party. OAuth achieves this by introducing an authorization layer and separating the role of the client from that of the resource owner. OAuth defines four primary roles:

    *  **Resource owner** (RO): The entity that can _grant access_ to a **protected resource** exposed by an API.  Typically this is the end-user.  
    *  **Client**: The mobile application, web site, and so on, that wants to access a **protected resource** on behalf of the **resource owner**.
    *  **Authorization server** (AS): The Security Token Service (STS) or OAuth server that issues **tokens**.  The authorization server will typically have two primary URLs, one for the authorization request and one for applications to use to grant access tokens. These are usually something such as:  
            *https://authorization-server.com/authorize*  
            **https://authorization-server.com/token**
    *  **Resource server** (RS):   The server _hosting_ the **protected resources**. This is the _API_ you want to access.  Resource servers rely on some kind of information to decide whether access to a protected resource should be _granted_. For RESTful-based resource servers, that information is usually carried in a _security token_, typically sent as a **bearer token** along with every request to the server. Web applications that rely on a session to authenticate users usually store that information in the user’s session and retrieve it from there for each request    

*   **Bearer Token** A security token with the property that any party in possession of the token (a "bearer") can use the token in any way that any other party in possession of it can. Using a bearer token does not require a bearer to prove possession of cryptographic key material (proof-of-possession).  
    *   **Access token** is the token provided by the authorization server that provide access to Protected Resources. The token has a corresponding duration of access, scope, and potentially other information the server needs.  
    *   **Refresh token** is a token that is used to get a new access token when an access token expires. Not all APIs use refresh tokens.  
    *   **Authorization code** is an intermediate token used in the server-side app flow. An authorization code is returned to the client after the authorization step, and then the client exchanges it for an access token.  
*   **Scopes** A user can grant _scoped_ access to their account, which can vary depending on the operation the client application wants to perform. Each OAuth access token (  **Bearer Token** ) can be tagged with multiple **scopes**. Scopes are _access rights_ that control whether the credentials a user provides allow to perform the needed call to the resource server. _Example_ :
    1.  Read: Grant read-only access to all your data except for the account and user info
    2.  Write: Grant write-only access to all your data except for the account and user info
    3.  Profile: Grant read-only access to the account and user info only   

*   **Verifying Scope:** The resource server needs to know the list of scopes that are associated with the access token. The server is responsible for denying the request if the scopes in the access token do not include the required scope to perform the designated action.The OAuth 2.0 spec does not define any scopes itself, nor is there a central registry of scopes. The list of scopes is up to the service to decide for itself.
*   **Error Codes and Unauthorized Access**  If the access token does not allow access to the requested resource, or if there is no access token in the request, then the server must reply with an **HTTP 401 response** and include a **WWW-Authenticate header** in the response.The minimum WWW-Authenticate header includes the string **Bearer**, indicating that a bearer token is required. The header can also indicate additional information such as a “**realm**” and “**scope**”. The “realm” value is used in the traditional [HTTP authentication](https://tools.ietf.org/html/rfc2617) sense. The “scope” value allows the resource server to indicate the list of scopes required to access the resource, so the application can request the appropriate scope from the user when starting the authorization flow. The response should also include an appropriate “error” value depending on the type of error that occurred.  

            invalid_request (HTTP **400**) – The request is missing a parameter, or is otherwise malformed.  
            invalid_token (HTTP **401**) – The access token is expired, revoked, malformed, or invalid for other reasons. The client can obtain a new access token and try again.  
            insufficient_scope (HTTP **403**) – The access token does not contain the requested scope

*   **What is JWT?**  JSON Web Token (_**JWT**_) is a  type of **bearer** token  representing **claims** to be transferred between two parties. The claims in a **_JWT_ **are encoded as a  JSON object that is used as the payload of a JSON Web Signature (_**JWS**_) structure or as the plaintext of a JSON Web Encryption (_**JWE**_) structure, enabling the  claims to be digitally signed or integrity protected with a Message Authentication Code (MAC) and/or encrypted.  

*   **JWT Signature:** To create the _**JWT signature**_ you  take the encoded **header**, the encoded **payload**, a **secret**, the algorithm specified in the header and sign that. _The algorithm is part of the JWT header, for example :_
    *   **RS256**  (RSA Signature with [SHA-256](https://en.wikipedia.org/wiki/SHA-256))   is an [asymmetric algorithm](https://en.wikipedia.org/wiki/Public-key_cryptography) which means that there are two keys: one public and one private (secret). Auth Server has the secret key, which is used to generate the signature, and the consumer of the JWT has the public key, which is used to validate the signature.
    *   **HS256**   ([HMAC](https://en.wikipedia.org/wiki/HMAC) with SHA-256)  is a [symmetric algorithm](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) which means that there is only one secret key, shared between the two parties. The same key is used both to generate the signature and to validate it. Special care should be taken in order for the key to remain confidential
    *   The most secure practice is to use **RS256**. Some of the reasons are:
        *   With RS256 you are sure that only the holder of the private key Auth Server can sign tokens, while anyone can check if the token is valid using the public key.
        *   Under HS256, if the secret key is compromised (e.g. by the application) you would have to re-deploy the API with the new secret.
        *   With RS256 you can request a token that is valid for multiple audiences.
        *   With RS256 you can implement key rotation without having to re-deploy the API with the new secret.

*   **OpenID Connect** is specified in the [OpenID Connect 1.0 specification](http://openid.net/specs/openid-connect-core-1_0.html). OpenID Connect builds on the OAuth protocol and defines an interoperable way to use OAuth 2.0 to perform user authentication. OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It enables clients to verify the identity of the user based on the authentication performed by an authorization server, as well as to obtain basic profile information about the user.OpenID Connect defines the following roles:
    *   _**Relying party (RP)**_: An OAuth client that supports OpenID Connect. The mobile application, web site, and so on, that wants to access data on behalf of the resource owner.
    *   _**OpenID provider (OP)**_: An OAuth authorization server that is capable of authenticating the user and providing claims to a relying party about the authentication event and the user.  _**OpenID Connect**_ defines a new kind of token, the **ID token**. The OpenID Connect _**ID token**_ is a _**signed JSON Web Token (JWT)**_ that is given to the client application alongside the regular _OAuth access token_. The ID token contains a set of _claims_ about the authentication session, including an identifier for the user (sub), an identifier for issuer of the token (iss), and the identifier of the client for which this token was created (aud). Since the format of the ID token is known by the client, it can parse the content of the token directly.In addition to the claims in the ID token, OpenID Connect defines a standard protected resource (the UserInfo endpoint) that contains claims about the current user. OpenID Connect defines a set of standardized OAuth scopes that map to claims (profile, email, phone, and address). If the end user authorizes the client to access these scopes, the OP releases the associated data (claims) to the client when the client calls the UserInfo endpoint. OpenID Connect also defines a special openid scope that switches the OAuth server into OpenID Connect mode.  

*   **OAuth** _vs_ **OpenID Connect (OIDC)** - OAuth 2.0 and OpenID Connect (OIDC) are often mistaken for the same thing, but this is not exact.
    *   **OAuth 2.0** is a protocol that lets you authorize one website (the consumer or application) to access your data from another website (the resource server or provider). For example, you want to authorize a website to access some files from your Dropbox account. The website will redirect you to Dropbox which will ask you whether it should provide access to your files. If you agree the website will be authorized to access your files from Dropbox. At the core, OAuth 2.0 is about resource access and sharing.
    *   **OpenID Connect**, on the other hand, is a simple identity layer built on top of the OAuth 2.0 protocol. It gives you one login for multiple sites. Each time you need to log in to a website using OIDC, you are redirected to your OpenID site where you login, and then taken back to the website. At the core, OIDC is concerned with user authentication.    

*   **More on tokens**
    *   Tokens are alphanumeric strings used in token-based authentication. They allow users to authenticate with a username and password once and get a token in return which they can use from that point on. They have a limited lifetime duration.**JSON Web Tokens (JWTs)** are tokens that conform to the [JSON Web Token Standard](https://tools.ietf.org/html/rfc7519) and contain information about an identity in the form of claims. They are **self-contained** in that it is not necessary for the recipient to call a server to validate the token. JWTs can be signed using a secret (with the **HMAC** algorithm) or a public/private key pair using **RSA**.
    *   A JWT Token contains three parts: A header, a body and a signature.
        *   The header contains the type of token and the hash algorithm used on the contents of the token.
        *   The body, also called the **payload**, contains identity **claims** about a user. There are some claims with registered names, for things like the issuer of the token, the subject of the token (who the claims are about), and the time of issuance. Any number of additional claims with other names can be added, though care must be taken to keep the JWT within the browser size limitations for URLs.
        *   The signature is used by the recipient of a JWT to validate the integrity of the information conveyed in the JWT.  

    *   **Access Tokens**  
          Access Tokens are credentials that can be used by an application to access an API. Access Tokens can be an opaque string, JWT, or non-JWT token. Its purpose is to inform the API that the bearer of this token has been granted delegated access to the API and request specific actions (as specified by the scopes that have been granted).  

    *   **ID Tokens**  
          The ID Token is a JSON Web Token (JWT) that contains identity data. It is consumed by the application and used to get user information like the user's name, email, and so forth, typically used for UI display. ID Tokens conforms to an industry standard (IETF RFC 7519) and contain three parts: a header, a body and a signature.  

*   **Claims**  
      JWT Tokens contain claims, which are statements (such as name or email address) about an entity (typically, the user) and additional metadata.

*   **Verify Access Tokens** for Custom APIs
    *   Check that the JWT is well formed
    *   Check the signature
    *   Validate the standard claims
    *   Check the Application permissions (scopes)

*   **Basic OAuth 2 Flow**
    *   The Client requests access to the Resource Server by calling the Authorization Server.
    *   The Authorization Server redirects to allow the user to authenticate, which is usually performed within a browser. This is essentially signing into an authorization server, not the app.
    *   The Authorization Server then validates the user credentials and provides an Access Token to client, which can be use to call the Resource Server
    *   The Client then sends the Token to the Resource Server
    *   The Resource Server asks the Authorization Server if the token is valid.
    *   The Authorization Server validates the Token, returning relevant information to the Resource Server i.e. time till token expiration, who the token belongs too.
    *   The Resource Server then provides data to the Client.  The generated Access Token contains all relevant information for role authorization.  
              **AuthToken**  
               token: String (The token itself)  
               username : String (The name of the requester)  
               roles : String[] (The available roles for the requester)  
               scope: String  (  Multiple scopes are separated with whitespace )

*   **Basic OpenID Connect Flow**
    *   The Client requests access to the Resource Server by calling the Open ID Connect enabled Authorization Server.
    *   The Authorization Server redirects to allow the user to authenticate.
    *   The Authorization Server then validates the user credentials and provides an Access Token AND an ID Token to the client.
    *   The Client uses this ID Token to enhance the UX and typically stores the user data in it’s own session.
    *   The Client then sends the Access Token to the Resource Server
    *   The Resource Server responds, delivering the data to the Client.The additional ID token contains information about the user, suchs as name and assigned roles.      

*   _Oauth2 Flows_ (also called _grant types_) are scenarios an API client performs to get an access token from the authorization server. OAuth 2.0 provides several flows suitable for different types of API clients:
    *   **Authorization code** – The most common flow, mostly used for server-side and mobile web applications. This flow is similar to how users sign up into a web application using their Facebook or Google account.
    *   **Implicit** – This flow requires the client to retrieve an access token directly. It is useful in cases when the user’s credentials cannot be stored in the client code because they can be easily accessed by the third party. It is suitable for web, desktop, and mobile applications that do not include any server component.
    *   **Resource owner password credentials** (or just **password**) – Requires logging in with a username and password, via Resource Server API.   Since in that case the credentials will be a part of the request, this flow is suitable only for trusted clients.
    *   **Client Credentials** – Intended for the server-to-server authentication, this flow describes an approach when the client application acts on its own behalf rather than on behalf of any individual user. In most scenarios, this flow provides the means to allow users specify their credentials in the client application, so it can access the resources under the client’s control.

*   **SAML** **Security Assertion Markup Language**  is an [open standard](https://en.wikipedia.org/wiki/Open_standard) for exchanging [authentication](https://en.wikipedia.org/wiki/Authentication) and [authorization](https://en.wikipedia.org/wiki/Authorization) data between parties, in particular, between an [identity provider](https://en.wikipedia.org/wiki/Identity_provider_(SAML)) and a [service provider](https://en.wikipedia.org/wiki/Service_provider_(SAML)).   The Service Provider agrees to trust the Identity Provider to authenticate users. The Identity Provider authenticates users and provides to Service Providers an Authentication Assertion that indicates a user has been authenticated.                                                                 [SAML 2.0](http://saml.xml.org/saml-specifications) is a similar specification to **OpenID Connect**  but a lot older and more mature. It has its roots in SOAP and the WS-* specifications so it tends to be a bit more verbose than  **OpenID Connect**  . SAML 2.0 is primarily an authentication protocol that works by exchanging XML documents between the authentication server and the application. XML signatures and encryption are used to verify requests and responses  
    *   **A Service Provider (SP)** is the entity providing the service – typically in the form of an application    

    *   **An Identity Provider (IDP)** is the entity providing the identities, including the ability to authenticate a user. The Identity Provider typically also contains the user profile – additional information about the user such as first name, last name, job code, phone number, address, etc.    

    *   **A SAML Request**, also known as an authentication request, is generated by the Service Provider to “request” an authentication.    

    *   **A SAML Response** is generated by the Identity Provider. It contains the actual assertion of the authenticated user. In addition, a SAML Response may contain additional information, such as user profile information and group/role information, depending on what the Service Provider can support.    
        The single most important use case that SAML addresses is [web browser](https://en.wikipedia.org/wiki/Web_browser) [single sign-on](https://en.wikipedia.org/wiki/Single_sign-on) (SSO)  
