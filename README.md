


## Configuration

* Needs
  * TRUENAS_URL
  * TRUENAS_API_KEY
  * PERSIST_DIR
    * Contains configuration and certificate files

Example certdist.yaml:

```yaml
connection:
  server: "https://your-server.com"
age_key:
  # public_key: <optional, auto-generated from private-key>
  private_key: "AGE-SECRET-KEY-1..."
certificate:
  - domain: "example.com"
    # this directory must match the certdist-truenas command below
    directory: "/config/"
    renew_commands:
      - "/certdist-truenas -cert /config/fullchain.pem -key /config/privkey.pem "
```

