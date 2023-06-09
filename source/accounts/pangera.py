import os
import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Audit

# Read your project domain from an env variable
domain = os.getenv("PANGEA_DOMAIN")

# Read your access token from an env variable
token = os.getenv("PANGEA_TOKEN")

# Create a Config object contain the Audit Config ID
config = PangeaConfig(domain=domain)

# Initialize an Audit instance using the config object
audit = Audit(token, config=config)

# Create test data
# All input fields are listed, only `message` is required
print(f"Logging...")
try:
    # Create test data
    # All input fields are listed, only `message` is required
    log_response = audit.log(
        message="despicable act prevented",
        action="reboot",
        actor="villan",
        target="world",
        status="error",
        source="some device",
        verbose=True
    )
    print(f"Response: {log_response.result}")
except pe.PangeaAPIException as e:
    # Catch exception in case something fails
    print(f"Request Error: {e.response.summary}")
    for err in e.errors:
        print(f"\t{err.detail} \n")

