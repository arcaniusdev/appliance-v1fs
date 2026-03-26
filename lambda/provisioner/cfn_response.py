import json
import logging
import urllib.request

logger = logging.getLogger(__name__)


def send(event, context, status, data=None, reason=None, physical_resource_id=None):
    body = {
        "Status": status,
        "Reason": reason or f"See CloudWatch Log Stream: {context.log_stream_name}",
        "PhysicalResourceId": physical_resource_id or context.log_stream_name,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Data": data or {},
    }
    body_bytes = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        event["ResponseURL"],
        data=body_bytes,
        headers={"Content-Type": ""},
        method="PUT",
    )
    try:
        urllib.request.urlopen(req, timeout=30)
        logger.info("CFN response sent: %s", status)
    except Exception:
        logger.exception("Failed to send CFN response")
