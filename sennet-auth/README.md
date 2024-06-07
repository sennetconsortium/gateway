## HuBMAP Auth

This is the HuBMAP Auth service written in Python Flask served with uWSGI application server in conjunction with Nginx (as reverse proxy) in a docker container. All requests of HuBMAP API services and File service that require authentication and authorization will come to this gateway first.

### Flask config

The Flask application confiuration file `app.cfg` is located under `instance` folder. You can read more about [Flask Instance Folders](http://flask.pocoo.org/docs/1.0/config/#instance-folders). In this config file, you can specify the following items:

````
# File path of API endpoints json file, DO NOT MODIFY
API_ENDPOINTS_FILE = '/usr/src/app/api_endpoints.json'

# Globus app client ID and secret
GLOBUS_APP_ID = ''
GLOBUS_APP_SECRET = ''

# Globus Hubmap-Read group UUID
# Used for file service
GLOBUS_HUBMAP_READ_GROUP_UUID = ''

# URL base to entity-api for getting file access level of a given dataset UUID
# Default value works for docker localhost
# Works regardless the trailing slash /
ENTITY_API_URL = 'http://localhost:3333/entity-access-level/'

# The maximum integer number of entries in the cache queue
CACHE_MAXSIZE = 128
# Expire the cache after the time-to-live (seconds)
CACHE_TTL = 7200
````

### uWSGI config

In the `hubmap-auth/Dockerfile`, we installed uWSGI and the uWSGI Python plugin via yum. There's also a uWSGI configuration file `src/uwsgi.ini` and it tells uWSGI the details of running this Flask app. No need to modify.

### Nginx config

Nginx serves as the reverse proxy and passes the requests to the uWSGI server. The nginx configuration file for this service is located at `nginx/conf.d-dev/hubmap-auth.conf` or `nginx/conf.d-prod/hubmap-auth.conf` under the root project. This file defines how the `hubmap-auth` container handles the API requests via nginx using the `auth_request` module.


### API endpoints lookup and caching

For API auth of the Web Gateway, we'll need a json file named `api_endpoints.json` defined in the `instance/app.cfg` that specifies all the details for matching endpoints. Public endpoints don't require any authentication. However, the private endpoints will require the globus token in the `Authorization` header or the custom `MAuthorization` HTTP header. Certain endpoints that require certain group access will also require the globus group access token. 

Note: this endpoints file will be mounted to the docker container when we spin up the service. The mount point is defined in the docker-compose ymal file based on your environment.

When the API client/consumer sends out the `Authorization` HTTP header, a valid token should be used:

````
Authorization: Bearer u8kr4P3XwePdWgoJ2N7Q9MDMNQK5MDgMNWYe2on5xQEVyQPlxpIqCOjYoX41qXyYEdQzVN9np2jQMniPpDJ74c7LXztq9mYc10GQU6d0x
````

Note this token needs to be a group access token (nexus token) if the requested endpoint requires group access, otherwise a regular auth token works.

To make the lookup of a given endpoint more efficent, we enabled caching. The caching settings can be found in the `instance/app.cfg` file:

````
# The maximum integer number of entries in the cache queue
CACHE_MAXSIZE = 128
# Expire the cache after the time-to-live (seconds)
CACHE_TTL = 7200
````

When the data source of the `endpoints.json` gets updated, we'll need to clear the cache by calling this endpoint (in the case of local development mode):

````
GET http://localhost:8080/cache_clear
````

### File assets service

The File Assets service allows direct http(s) access to files located in HuBMAP datasets with access control via passing an auth token via a header in the standard `Authorization: Bearer <token>` mechanism or by adding the token directy as a URL parameter.

  URL pattern: `https://assets.hubmapconsortium.org/<dataset-uuid>/<relative-file-path>?token=<globus-token>`

#### File assets status

There's a json filed named `file_assets_status.json` under `src/static` will need to be placed on the file system where the file assets runs for the status check.
