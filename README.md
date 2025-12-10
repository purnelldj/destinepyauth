# destinepyauth

A Python library for authenticating against DESP (Destination Earth Service Platform) services.

## Installation

```bash
pip install destinepyauth
```

For development:

```bash
pip install -e ".[dev]"
```

## Usage

The main entry point is the `get_token()` function:

```python
from destinepyauth import get_token

# Interactive authentication (prompts for credentials)
result = get_token("highway")

# With credentials
result = get_token("highway", username="user@example.com", password="secret")

# Access the token
token = result.access_token
```

### Using with requests

```python
from destinepyauth import get_token
import requests

result = get_token("eden")
headers = {"Authorization": f"Bearer {result.access_token}"}
response = requests.get("https://api.example.com/data", headers=headers)
```

### Using with zarr/xarray (netrc support)

For services like CacheB that work with zarr, you can write credentials to `~/.netrc`:

```python
from destinepyauth import get_token
import xarray as xr

# Authenticate and write to ~/.netrc
get_token("cacheb", write_netrc=True)

# Now zarr/xarray will use credentials automatically
ds = xr.open_dataset(
    "reference://",
    engine="zarr",
    backend_kwargs={
        "consolidated": False,
        "storage_options": {
            "fo": "https://cacheb.dcms.destine.eu/path/to/data.json",
            "remote_protocol": "https",
            "remote_options": {"client_kwargs": {"trust_env": True}},
        },
    },
)
```

## Available Services

- `cacheb` - CacheB data service
- `dea` - DEA service
- `eden` - Eden broker
- `highway` - Highway service (includes token exchange)
- `insula` - Insula service
- `streamer` - Streaming service

## Configuration

Credentials can be provided via:

1. Function arguments (`username`, `password`)
2. Environment variables (`DESPAUTH_USER`, `DESPAUTH_PASSWORD`)
3. Interactive prompt (if not provided elsewhere)

## License

BSD-3-Clause
