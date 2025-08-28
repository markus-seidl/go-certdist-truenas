
# go-certdist-truenas

Certdist "plugin" (=App) for TrueNAS, which automatically updates the certificate of your TrueNAS instance.

## Configuration

* Needs
  * TRUENAS_URL
  * TRUENAS_API_KEY
  * PERSIST_DIR
    * Contains configuration and certificate files

Example certdist config.yml:

```yaml
connection:
  server: "https://your-server.com"
age_key:
  # public_key: <optional, auto-generated from private-key>
  private_key: "AGE-SECRET-KEY-1..."
certificate:
  - domain: "example.com"
    # this directory must match the certdist-truenas command below and also the PERSIST_DIR environment variable
    directory: "/config/"
    renew_commands:
      - "/certdist-truenas -cert /config/fullchain.pem -key /config/privkey.pem "
```

## Installation in TrueNAS

We are using the custom apps feature of TrueNAS.

* Prerequisites:
  * You need a directory that contains the config.yaml and for the current certificate/key. It should be only accessible to the container and to you for administrative purposes. (It will contain the certificate private key!)
  * A valid certdist client configuration file (see example above)
  * A TrueNAS admin API key
* Installation
  * TrueNAS Admin UI -> Apps -> Discover Apps -> Custom App
  * Application Name: certdist
  * Repository: `ghcr.io/markus-seidl/go-certdist-truenas`
  * Tag: The release tag you want to install, or "latest" if you want auto update (Note: then you also need to update the pull policy)
  * Timezone: Your timezone
  * Environment Variables:
    * TRUENAS_URL: https://your-truenas-url
    * TRUENAS_API_KEY: Your TrueNAS admin API key
    * PERSIST_DIR: /config
  * Restart Policy: unless-stopped
  * Storage Configuration
    * Probably Host Path 
    * Mount Path: /config
    * Add your config directory and map it to /config
      * Ensure that the user the container runs in, is allowed to write to the /config path (!)
* Note: When the certificate update is successful you will be logged out of the admin UI, maybe right after the installation. This is required because of the installation of the new certificate, which requires a WebUI restart.


