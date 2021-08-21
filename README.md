# go-jwt-auth

This repo is a part of a RESTful authorization service written in Go with MongoDB as the database.

There are two routes:

/get-tokens?user-uuid=<user-uuid> - issues a pair: one access token and one refresh token and then loads the hash of the refresh token to the databse.
Access token is a [JWT](https://jwt.io/) and can be used to authorize further user requests.
Refresh token is of a custom type and can be used to get a new pair of tokens when the access token expires.

/refresh-tokens - refreshes a pair of tokens if the submitted pair is valid.
A pair is valid if: access token is valid and possibly expired; refresh token is valid, not expired, and is in the database.

All the configuration parameters, including the secret keys for signing tokens are inside the `config.yaml` file.
To run the program, use `go run .`.
