# SenNet Hybrid Gateway Overview

This HuBMAP Gateway serves as an authentication and authorization gateway for some of the HuBMAP API services and File assets service, it also proxies the requests to the UI applications. 

HTTP requests to the following APIs will be proxied to this gateway service for authentication and authorization against Globus Auth before reaching to the target endpoints. 

- [Ingest API](https://github.com/hubmapconsortium/ingest-api)

The file assets service is not an API per se, the gateway only does the auth cehck for requests made to

- `https://assets.hubmapconsortium.org/<uuid>/<relative-file-path>[?token=<globus-token>]`


## Docker build for DEV development

There are a few configurable environment variables to keep in mind:

- `COMMONS_BRANCH`: build argument only to be used during image creation when we need to use a branch of commons from github rather than the published PyPI package. Default to main branch if not set or null.
- `HOST_UID`: the user id on the host machine to be mapped to the container. Default to 1001 if not set or null.
- `HOST_GID`: the user's group id on the host machine to be mapped to the container. Default to 1001 if not set or null.


Note: Environment variables set like this are only stored temporally. When you exit the running instance of bash by exiting the terminal, they get discarded. So for rebuilding the docker image, we'll need to make sure to set the environment variables again if necessary.

```
cd docker
./docker-development.sh [check|config|build|start|stop|down]
```

## Docker build for deployment on PROD

```
cd docker
./docker-deployment.sh [start|stop|down]
```
