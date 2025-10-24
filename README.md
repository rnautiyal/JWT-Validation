---
title: JWT validation in Azure Application Gateway
description: Learn how to configure JSON Web Token (JWT) validation in Azure Application Gateway to enforce authentication and authorization policies.
author: rnautiyal
ms.author: rnautiyal
ms.service: azure-application-gateway
ms.topic: conceptual
ms.date: 10/22/2025
---

# JWT (JSON WEB TOKEN) validation in Azure Application Gateway (Preview)

### Overview
Azure Application Gateway provides built-in JSON Web Token (JWT) validation at the gateway level.
This capability verifies the integrity and authenticity of tokens in incoming requests and determines whether to allow or deny access before forwarding traffic to backend services. Upon successful validation, the gateway injects the x-msft-entra-identity header into the request and forwards it to the backend, enabling downstream applications to securely consume verified identity information.

By performing token validation at the edge, Application Gateway simplifies application architecture and strengthens overall security posture. JWT validation is stateless, meaning each request must present a valid token for access to be granted. No session or cookie-based state is maintained, ensuring consistent validation across requests and alignment with Zero Trust security principles.

With JWT validation, Application Gateway can:
- Verify token integrity using a trusted issuer and signing keys.
- Validate claims such as audience, issuer, and expiration.
- Block requests with invalid or missing tokens before they reach your backend.

### Why use JWT validation?
- **Zero Trust alignment:** Ensure only authenticated traffic reaches your application.
- **Simplified architecture:** Offload token validation from backend services.
- **Improved security:** Reduce attack surface and prevent unauthorized access.

### Supported scenarios
- Validate JWT tokens in the `Authorization` header.
- Provide an allow or deny decision based on token validity.

> [!NOTE]
> Tokens must be issued by Microsoft Entra ID

### Configure JWT validation

### Step 1: Register an application in Microsoft Entra ID
1. Go to [Azure Portal → App registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade).
2. Select **New registration**.
3. Enter:
   - **Name:** `appgw-jwt-demo`
   - **Supported account types:** *Accounts in this organizational directory only*.
4. Select **Register**.
5. Copy:
   - **Application (client) ID** → `CLIENT_ID`
   - **Directory (tenant) ID** → `TENANT_ID`.



### Step 2: Configure JWT validation in Application Gateway
1. Open the preview configuration portal:  
   [App Gateway JWT Config Portal](https://ms.portal.azure.com/?feature.canmodifystamps=true&amp;Microsoft_Azure_HybridNetworking=flight23&amp;feature.applicationgatewayjwtvalidation=true).
2. Select **JWT validation configuration**.
3. Provide the following details:

| Field                    | Example                        | Description                                                              |
| ------------------------ | ------------------------------ | ------------------------------------------------------------------------ |
| **Name**                 | `jwt-validation-demo`          | Friendly name for the validation configuration                           |
| **Unauthorized Request** | Deny                           | Reject requests with missing or invalid JWTs                             |
| **Tenant ID**            | `<your-tenant-id>`             | Must be a valid GUID or one of `common`, `organizations`, or `consumers` |
| **Client ID**            | `<your-client-id>`             | GUID of the app registered in Entra                                      |
| **Audiences**            | (Optional) `api://<client-id>` | Enter audience claim configured at registration                          |

4. Associate the configuration with a **Routing rule** (see next section).


### Step 3: Create an HTTPS routing rule
1. Go to **Application Gateway → Rules → Add Routing rule**.
2. Configure:
   - **Listener:** Protocol `HTTPS`, assign certificate or Key Vault secret.
   - **Backend target:** Select or create a backend pool.
   - **Backend settings:** Use appropriate HTTP/HTTPS port.
   - **Rule name:** e.g., `jwt-route-rule`.
3. Link this rule to your JWT validation configuration.

Your JWT validation configuration is now attached to a secure HTTPS listener and routing rule.

### Step 4: Client request Validation with Azure Application Gateway

Any client request that reaches Application Gateway with an **Authorization header** containing an access token will be validated by Application Gateway.  
- If the JWT token is **valid**, the connection will be established.  
- If the token is **invalid**, the request will return **401 Unauthorized** or **403 Forbidden**.

### Optional: Verify the client request with JWT token

Once configuration is complete for testing, retrieve an access token using Azure CLI:

```bash
az login --tenant "<TENANT_ID>"

TOKEN=$(az account get-access-token \
    --scope "https://management.azure.com/.default" \
    --query accessToken -o tsv)
```
> [!NOTE]
> For the above scope, make sure the audience is set to `https://management.azure.com/`.  
> For more details, see [Microsoft identity platform and OAuth 2.0 authorization code flow](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-auth-code-flow).

### Verify client connectivity
```bash
curl -k -H "Authorization: Bearer $TOKEN" https://<appgwFrontendIpOrDns>:<listenerPort>/<pathToListenerWithRoute>
```


**Expected Response:**

* **200 OK** : JWT validated successfully
* **401 Unauthorized / 403 Forbidden** : Token invalid or expired  
  If you receive **401**, verify that the `aud` (audience) claim in the token matches  expected value.  
  You can check this using `awk` and `jq`:
  If you receive **403**, verify that the `exp` expiry in the token still valid 
  You can check this using `awk` and `jq`:

```bash
# Decode JWT and extract audience
echo $JWT_TOKEN | awk -F. '{print $2}' | base64 --decode | jq '.aud'
echo $JWT_TOKEN | awk -F. '{print $2}' | base64 --decode | jq '.exp'
```
### Next steps
To learn more about JWT validation and related identity features in Azure:

- [Understand JSON Web Tokens (JWT) in Microsoft Entra ID](https://learn.microsoft.com/azure/active-directory/develop/jwt)
- [Register an application in Microsoft Entra ID](https://learn.microsoft.com/entra/identity-platform/quickstart-register-app)
- [Azure Application Gateway overview](https://learn.microsoft.com/azure/application-gateway/)
- [Zero Trust security model overview](https://learn.microsoft.com/security/zero-trust/overview)
