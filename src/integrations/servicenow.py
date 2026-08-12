# Re-exported for backwards compatibility.
# The actual implementation moved to servicenow_client.py
# to avoid shadowing the servicenow/ package directory.
from src.integrations.servicenow_client import (
    ServiceNowClient,
    ServiceNowConfig,
    ServiceNowIncidentHandler,
    ServiceNowWorkflowIntegration,
)
