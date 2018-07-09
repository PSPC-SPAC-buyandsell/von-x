# API Methods

When using the built-in web server configuration, von-x currently offers two methods
for each connection. For issuer connections, the `issue-credential` method is provided:

```text
    /{CONNECTION_ID}/issue-credential?schema={SCHEMA_NAME}&version={SCHEMA_VERSION}
```
  
The schema version is optional. The body of the POST request must be a JSON-formatted
dictionary of the credential attributes.

***

For connections from a verifier agent, the `request-proof` method is offered:

```text
    /{CONNECTION_ID}/request-proof?name={PROOF_NAME}
```
  
The proof request specification for the given proof name must be registered in advance.
  
The body of this request may be a JSON-formatted dictionary of input parameters for the
proof request.

***

When connecting to an external TheOrgBook holder instance, API methods are used to store credentials
and construct proofs. Similar methods will be added for von-x holder services.

```text
    /indy/register-issuer
```

This method is called each time an TheOrgBook holder connection is established, to establish
credential types and other issuer information.

The body of the request must be a JSON-formatted issuer specification (defined by TheOrgBook).

***

Before storing a credential the following method is called to generate a credential request:

```text
    /indy/generate-credential-request
```
```json
    {
      "credential_offer": {"...indy credential offer json..."},
      "credential_definition": {"...indy credential definition..."}
    }
```

***

The credential is then stored using the following method:

```text
    /indy/store-credential
```
```json
    {
      "credential_type": "schema name",
      "credential_data": {"credential attributes": "attribute values"},
      "issuer_did": "issuer DID",
      "credential_definition": {"...indy credential definition..."},
      "credential_request_metadata": {"...indy credential request metadata..."}
    }
```

***

Finally, proof requests are performed using the following method:

```text
    /indy/construct-proof
```
```json
    {
      "source_id": "...TheOrgBook source ID...",
      "proof_request": {"...indy proof request..."},
      "cred_ids": ["...an optional list of credential IDs..."]
    }
```
