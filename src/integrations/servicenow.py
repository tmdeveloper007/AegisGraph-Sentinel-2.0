# Backward-compatibility shim: the real module is now servicenow_client.py
from src.integrations.servicenow_client import (
    ServiceNowClient,
    ServiceNowConfig,
    ServiceNowIncidentHandler,
    ServiceNowWorkflowIntegration,
)
