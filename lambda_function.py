"""
TMI Webhook Handler for AWS Lambda

This Lambda function handles webhook callbacks from TMI (Threat Model Intelligence).
It responds to challenge requests for webhook verification and logs all incoming events.
"""

import json
import logging
import os
import hmac
import hashlib
from typing import Dict, Any, Optional

# Configure logging for CloudWatch
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def verify_webhook_signature(payload: str, signature: str, secret: str) -> bool:
    """
    Verify the HMAC-SHA256 signature of a webhook payload.

    Args:
        payload: The raw request body as a string
        signature: The signature from the X-Webhook-Signature header (format: sha256=<hex>)
        secret: The HMAC secret key

    Returns:
        True if the signature is valid, False otherwise
    """
    if not signature or not secret:
        return False

    try:
        # TMI sends signature in format "sha256=<hex_digest>"
        # Strip the "sha256=" prefix if present
        if signature.startswith("sha256="):
            signature_hex = signature[7:]  # Remove "sha256=" prefix
        else:
            signature_hex = signature

        expected_signature = hmac.new(
            secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature_hex, expected_signature)
    except Exception as e:
        logger.error(f"Error verifying signature: {e}")
        return False


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for TMI webhook events.

    Args:
        event: Lambda event containing the API Gateway proxy request
        context: Lambda context object

    Returns:
        API Gateway proxy response with statusCode and body
    """
    try:
        # Log the raw event for debugging
        logger.info(f"Received event: {json.dumps(event)}")

        # Extract the request body
        body = event.get("body", "{}")
        if isinstance(body, str):
            payload = json.loads(body)
        else:
            payload = body

        # Log webhook headers for monitoring
        headers = event.get("headers", {})
        logger.info(f"Webhook headers: {json.dumps(headers)}")

        # Extract relevant webhook metadata
        event_type = headers.get(
            "x-webhook-event", headers.get("X-Webhook-Event", "unknown")
        )
        delivery_id = headers.get(
            "x-webhook-delivery-id", headers.get("X-Webhook-Delivery-Id", "unknown")
        )
        subscription_id = headers.get(
            "x-webhook-subscription-id",
            headers.get("X-Webhook-Subscription-Id", "unknown"),
        )

        logger.info(
            f"Event Type: {event_type}, Delivery ID: {delivery_id}, Subscription ID: {subscription_id}"
        )

        # Handle challenge request (no signature verification needed)
        if payload.get("type") == "webhook.challenge":
            challenge = payload.get("challenge")
            logger.info(f"Responding to webhook challenge: {challenge}")

            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"challenge": challenge}),
            }

        # Verify HMAC signature for regular webhook events
        hmac_secret = os.environ.get("hmac", "")
        webhook_signature = headers.get(
            "x-webhook-signature", headers.get("X-Webhook-Signature", "")
        )

        signature_valid = verify_webhook_signature(body, webhook_signature, hmac_secret)
        logger.info(f"Signature verification: {'PASSED' if signature_valid else 'FAILED'}")

        if not signature_valid:
            logger.warning(
                f"Invalid webhook signature for delivery {delivery_id}. "
                f"Signature: {webhook_signature[:20]}... (truncated)"
            )

        # Handle regular webhook events
        logger.info(f"Processing webhook event: {json.dumps(payload)}")

        # Log event details
        if "event_type" in payload:
            logger.info(f"Event type: {payload['event_type']}")
        if "resource_type" in payload:
            logger.info(f"Resource type: {payload['resource_type']}")
        if "timestamp" in payload:
            logger.info(f"Event timestamp: {payload['timestamp']}")

        # Return success response for events
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"status": "received"}),
        }

    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in request body: {e}")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Invalid JSON"}),
        }

    except Exception as e:
        logger.error(f"Error processing webhook: {e}", exc_info=True)
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Internal server error"}),
        }
