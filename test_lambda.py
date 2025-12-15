#!/usr/bin/env python3
"""
Local test script for the TMI webhook Lambda function.

This script tests the lambda_function.lambda_handler with simulated events.
"""

import json
import sys
import os
import hmac
import hashlib
from lambda_function import lambda_handler


def generate_signature(payload: str, secret: str) -> str:
    """Generate HMAC-SHA256 signature for test payload"""
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def test_challenge_request():
    """Test webhook challenge request handling"""
    print("\n=== Testing Challenge Request ===")

    event = {
        'body': json.dumps({
            'type': 'webhook.challenge',
            'challenge': 'test-challenge-12345'
        }),
        'headers': {
            'Content-Type': 'application/json',
            'User-Agent': 'TMI-Webhook/1.0'
        }
    }

    response = lambda_handler(event, None)

    print(f"Status Code: {response['statusCode']}")
    print(f"Response Body: {response['body']}")

    # Verify response
    body = json.loads(response['body'])
    assert response['statusCode'] == 200, "Expected status code 200"
    assert body['challenge'] == 'test-challenge-12345', "Challenge mismatch"

    print("✅ Challenge request test PASSED")
    return True


def test_event_notification():
    """Test webhook event notification handling with valid signature"""
    print("\n=== Testing Event Notification (Valid Signature) ===")

    # Set test HMAC secret
    test_secret = "test-hmac-secret-key"
    os.environ["hmac"] = test_secret

    payload_dict = {
        'event_type': 'threat_model.created',
        'threat_model_id': 'tm-123',
        'resource_id': 'res-456',
        'resource_type': 'threat_model',
        'owner_id': 'user-789',
        'timestamp': '2025-12-14T10:00:00Z',
        'data': {
            'name': 'Test Threat Model',
            'description': 'A test threat model'
        }
    }

    body_str = json.dumps(payload_dict)
    signature = generate_signature(body_str, test_secret)

    event = {
        'body': body_str,
        'headers': {
            'Content-Type': 'application/json',
            'X-Webhook-Event': 'threat_model.created',
            'X-Webhook-Delivery-Id': '123e4567-e89b-12d3-a456-426614174000',
            'X-Webhook-Subscription-Id': '123e4567-e89b-12d3-a456-426614174001',
            'X-Webhook-Signature': signature,
            'User-Agent': 'TMI-Webhook/1.0'
        }
    }

    response = lambda_handler(event, None)

    print(f"Status Code: {response['statusCode']}")
    print(f"Response Body: {response['body']}")

    # Verify response
    body = json.loads(response['body'])
    assert response['statusCode'] == 200, "Expected status code 200"
    assert body['status'] == 'received', "Expected status 'received'"

    print("✅ Event notification (valid signature) test PASSED")
    return True


def test_event_notification_invalid_signature():
    """Test webhook event notification handling with invalid signature"""
    print("\n=== Testing Event Notification (Invalid Signature) ===")

    # Set test HMAC secret
    test_secret = "test-hmac-secret-key"
    os.environ["hmac"] = test_secret

    event = {
        'body': json.dumps({
            'event_type': 'threat_model.created',
            'threat_model_id': 'tm-123',
            'resource_id': 'res-456',
            'resource_type': 'threat_model',
            'owner_id': 'user-789',
            'timestamp': '2025-12-14T10:00:00Z'
        }),
        'headers': {
            'Content-Type': 'application/json',
            'X-Webhook-Event': 'threat_model.created',
            'X-Webhook-Delivery-Id': '123e4567-e89b-12d3-a456-426614174000',
            'X-Webhook-Subscription-Id': '123e4567-e89b-12d3-a456-426614174001',
            'X-Webhook-Signature': 'invalid-signature-12345',
            'User-Agent': 'TMI-Webhook/1.0'
        }
    }

    response = lambda_handler(event, None)

    print(f"Status Code: {response['statusCode']}")
    print(f"Response Body: {response['body']}")

    # Should still return 200 but log the failure
    body = json.loads(response['body'])
    assert response['statusCode'] == 200, "Expected status code 200"
    assert body['status'] == 'received', "Expected status 'received'"

    print("✅ Event notification (invalid signature) test PASSED")
    return True


def test_invalid_json():
    """Test handling of invalid JSON"""
    print("\n=== Testing Invalid JSON ===")

    event = {
        'body': 'invalid json {{{',
        'headers': {
            'Content-Type': 'application/json'
        }
    }

    response = lambda_handler(event, None)

    print(f"Status Code: {response['statusCode']}")
    print(f"Response Body: {response['body']}")

    # Verify response
    assert response['statusCode'] == 400, "Expected status code 400"

    print("✅ Invalid JSON test PASSED")
    return True


def test_empty_body():
    """Test handling of empty body"""
    print("\n=== Testing Empty Body ===")

    event = {
        'body': '{}',
        'headers': {
            'Content-Type': 'application/json'
        }
    }

    response = lambda_handler(event, None)

    print(f"Status Code: {response['statusCode']}")
    print(f"Response Body: {response['body']}")

    # Should return 200 for empty event
    body = json.loads(response['body'])
    assert response['statusCode'] == 200, "Expected status code 200"
    assert body['status'] == 'received', "Expected status 'received'"

    print("✅ Empty body test PASSED")
    return True


def main():
    """Run all tests"""
    print("Starting TMI Webhook Lambda Function Tests")
    print("=" * 50)

    tests = [
        test_challenge_request,
        test_event_notification,
        test_event_notification_invalid_signature,
        test_invalid_json,
        test_empty_body
    ]

    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"❌ Test FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"❌ Test ERROR: {e}")
            failed += 1

    print("\n" + "=" * 50)
    print(f"Tests completed: {len(tests) - failed}/{len(tests)} passed")

    if failed > 0:
        print(f"❌ {failed} test(s) failed")
        sys.exit(1)
    else:
        print("✅ All tests passed!")
        sys.exit(0)


if __name__ == '__main__':
    main()
