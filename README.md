# Session - Go JWT wrapper

A Go JWT wrapper which bundles common operations for JWT tokens. Makes pervasive use of [Dave Grijalva]'s [jwt-go] Go implementation of JSON Web Tokens (JWT).

## What?
This provides functionality to create custom map claims, new JWTs, validity checks, refresh JWTs and check JWT content. It was built and intended for use with [auth] but can be used as a standalone.

## Why?
This was part of a learning exercise to create [auth] which is a very rough Go equivalent of dotnet core Identity services.

## How?
See the tests for usage examples.

## Examples
See [examples] for a http/appengine implementations which uses session and auth. This is written for appengine standard 2nd gen, but also works as a standalone.

## Dependencies and services
This utilises the following fine pieces of work:
* [Dave Grijalva]'s [jwt-go] Go implementation of JSON Web Tokens (JWT)
* [Segment]'s [ksuid] - K-Sortable Globally Unique IDs
* [GCP]'s [Datastore Go client] and [Storage Go client]
 
Also uses:
* [lidstromberg] packages [log], [keypair] and [config]. Please note the configuration requirements for these packages also. The easiest way to ensure all of these things are configured, is to refer to the [auth] package itself.

## Installation
Install using go get.

```sh
$ go get -u github.com/lidstromberg/session
```
#### Environment Variables
You will also need to export (linux/macOS) or create (Windows) some environment variables.

```sh
################################
# SESSION
################################
export JWT_ISSUER="{{DOMAINNAME}}"
export JWT_EXTMIN="15"
export JWT_APPROLEDELIM=":"

################################
# GCP DETAILS
################################
export LBAUTH_GCP_PROJECT="{{PROJECTNAME}}"
export LBAUTH_GCP_BUCKET="{{BUCKETNAME}}"
```
```sh
################################
# GCP CREDENTIALS
################################
export GOOGLE_APPLICATION_CREDENTIALS="/PATH/TO/GCPCREDENTIALS.JSON"
```
(See [Google Application Credentials])
```sh
################################
# AUTH DEBUG FLAG
# switch LB_DEBUGON to true to start verbose logging
################################
export LB_DEBUGON="false"
```

#### Private/Public Certs for JWT
If you want to run the authcore tests or the example implementations, then you will also require RSA certs for the [jwt-go] tokens. The following will generate them (assuming you have openssl installed). You should place a password on the private key when prompted.

```sh
$ ssh-keygen -t rsa -b 4096 -f jwt.key
$ openssl rsa -in jwt.key -pubout -outform PEM -pubout -out jwt.key.pub
```

#### Google Cloud Platform Requirements
If you intend to use GCP datastore as your backend, then you will require:
* A GCP project
* A GCP storage bucket (private) to store the jwt private/public keys (in the root of the bucket)
* Your GOOGLE_APPLICATION_CREDENTIALS json credentials key should be created with the following IAM scopes: 'Storage Object Viewer' and 'Storage Object Creator', or 'Storage Object Admin'.


   [Dave Grijalva]: <https://github.com/dgrijalva>
   [jwt-go]: <https://github.com/dgrijalva/jwt-go>
   [Segment]: <https://github.com/segmentio>
   [ksuid]: <https://github.com/segmentio/ksuid>
   [GCP]: <https://cloud.google.com/>
   [Storage Go client]: <https://cloud.google.com/storage/docs/reference/libraries#client-libraries-install-go>
   [Google Application Credentials]: <https://cloud.google.com/docs/authentication/production#auth-cloud-implicit-go>
   [lidstromberg]: <https://github.com/lidstromberg>
   [log]: <https://github.com/lidstromberg/log>
   [keypair]: <https://github.com/lidstromberg/keypair>
   [config]: <https://github.com/lidstromberg/config>
   [auth]: <https://github.com/lidstromberg/auth>
