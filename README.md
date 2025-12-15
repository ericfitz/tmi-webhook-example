# TMI Webhook Example - AWS Lambda

A simple AWS Lambda function that serves as a webhook endpoint for [TMI (Threat Model Intelligence)](https://github.com/ericfitz/tmi) integration.

## Features

- ✅ Responds to TMI webhook challenge requests for endpoint verification
- ✅ Verifies HMAC-SHA256 signatures for webhook events (logs verification status)
- ✅ Receives and logs all incoming webhook events to CloudWatch Logs
- ✅ Handles TMI webhook headers (event type, delivery ID, subscription ID)
- ✅ Proper error handling and JSON validation
- ✅ No external dependencies (uses only Python standard library)

## How It Works

The Lambda function handles two types of requests:

1. **Challenge Requests**: TMI sends a challenge request to verify your webhook endpoint. The function responds with the challenge value to complete verification. No signature verification is performed on challenge requests.

2. **Event Notifications**: TMI sends webhook events (e.g., `threat_model.created`) as POST requests with an HMAC-SHA256 signature in the `X-Webhook-Signature` header. The function:
   - Verifies the signature using the HMAC secret from the `hmac` environment variable
   - Logs whether signature verification passed or failed
   - Logs all event details to CloudWatch
   - Returns a success response regardless of signature validity (signature failures are logged for monitoring)

## Deployment Options

### Option 1: AWS Console Deployment

1. **Create a Lambda Function**:
   - Go to AWS Lambda Console
   - Click "Create function"
   - Choose "Author from scratch"
   - Function name: `tmi-webhook-handler`
   - Runtime: Python 3.12 (or latest available)
   - Click "Create function"

2. **Upload the Code**:
   - Copy the contents of `lambda_function.py`
   - Paste it into the Lambda code editor
   - Click "Deploy"

3. **Configure Environment Variables**:
   - In the Lambda function configuration, go to "Configuration" → "Environment variables"
   - Click "Edit" → "Add environment variable"
   - Key: `hmac`
   - Value: Your HMAC secret key (obtain this from your TMI webhook configuration)
   - Click "Save"

4. **Create an API Gateway Trigger**:
   - In the Lambda function configuration, click "Add trigger"
   - Select "API Gateway"
   - Create a new REST API or HTTP API
   - Security: Open (or configure authentication as needed)
   - Click "Add"
   - Note the API endpoint URL

5. **Configure TMI Webhook**:
   - Use the API Gateway endpoint URL as your webhook URL in TMI
   - Ensure the HMAC secret configured in TMI matches the `hmac` environment variable in Lambda

### Option 2: AWS SAM Deployment

Create a `template.yaml` file:

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Resources:
  TmiWebhookFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: tmi-webhook-handler
      Runtime: python3.12
      Handler: lambda_function.lambda_handler
      CodeUri: .
      Timeout: 30
      Events:
        WebhookApi:
          Type: HttpApi
          Properties:
            Path: /webhook
            Method: POST

Outputs:
  WebhookUrl:
    Description: "Webhook endpoint URL"
    Value: !Sub "https://${ServerlessHttpApi}.execute-api.${AWS::Region}.amazonaws.com/webhook"
```

Deploy with:
```bash
sam build
sam deploy --guided
```

### Option 3: Terraform Deployment

Create `main.tf`:

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"  # Change to your preferred region
}

# Lambda Function
resource "aws_lambda_function" "tmi_webhook" {
  filename         = "lambda_function.zip"
  function_name    = "tmi-webhook-handler"
  role            = aws_iam_role.lambda_role.arn
  handler         = "lambda_function.lambda_handler"
  source_code_hash = filebase64sha256("lambda_function.zip")
  runtime         = "python3.12"
  timeout         = 30
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "tmi-webhook-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# Attach basic Lambda execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# API Gateway HTTP API
resource "aws_apigatewayv2_api" "webhook_api" {
  name          = "tmi-webhook-api"
  protocol_type = "HTTP"
}

# API Gateway Stage
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.webhook_api.id
  name        = "$default"
  auto_deploy = true
}

# API Gateway Integration
resource "aws_apigatewayv2_integration" "lambda" {
  api_id             = aws_apigatewayv2_api.webhook_api.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.tmi_webhook.invoke_arn
  integration_method = "POST"
}

# API Gateway Route
resource "aws_apigatewayv2_route" "webhook" {
  api_id    = aws_apigatewayv2_api.webhook_api.id
  route_key = "POST /webhook"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

# Lambda Permission for API Gateway
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.tmi_webhook.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.webhook_api.execution_arn}/*/*"
}

# Output the webhook URL
output "webhook_url" {
  description = "Webhook endpoint URL"
  value       = "${aws_apigatewayv2_api.webhook_api.api_endpoint}/webhook"
}
```

Deploy with:
```bash
# Create deployment package
zip lambda_function.zip lambda_function.py

# Deploy
terraform init
terraform plan
terraform apply
```

## Testing the Webhook

### Test Challenge Request

```bash
curl -X POST https://your-api-gateway-url/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "type": "webhook.challenge",
    "challenge": "test-challenge-123"
  }'
```

Expected response:
```json
{
  "challenge": "test-challenge-123"
}
```

### Test Event Notification

```bash
curl -X POST https://your-api-gateway-url/webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Event: threat_model.created" \
  -H "X-Webhook-Delivery-Id: 123e4567-e89b-12d3-a456-426614174000" \
  -H "X-Webhook-Subscription-Id: 123e4567-e89b-12d3-a456-426614174001" \
  -d '{
    "event_type": "threat_model.created",
    "threat_model_id": "tm-123",
    "resource_type": "threat_model",
    "timestamp": "2025-12-14T10:00:00Z"
  }'
```

Expected response:
```json
{
  "status": "received"
}
```

## Monitoring

All webhook events are logged to CloudWatch Logs. To view logs:

1. Go to CloudWatch Console
2. Navigate to "Logs" → "Log groups"
3. Find `/aws/lambda/tmi-webhook-handler`
4. View the log streams to see all incoming requests

Logged information includes:
- Full request payload
- Webhook headers (event type, delivery ID, subscription ID)
- HMAC signature verification status (PASSED or FAILED)
- Event metadata (event type, resource type, timestamp)
- Any errors or exceptions

Example log entries:
```
INFO Signature verification: PASSED
INFO Event type: threat_model.created
```

Or for invalid signatures:
```
INFO Signature verification: FAILED
WARNING Invalid webhook signature for delivery 123e4567-...
```

## Security Considerations

### Implemented Security Features

- ✅ **Signature Verification**: The function verifies HMAC-SHA256 signatures on all webhook events using the `hmac` environment variable. Verification results are logged to CloudWatch.
  - Challenge requests are not signature-verified (as they are part of the initial handshake)
  - Invalid signatures are logged as warnings but do not reject the request (allows monitoring without breaking functionality)

### Additional Security Recommendations

- **Authentication**: The API Gateway is configured without authentication. Consider adding API keys or IAM authentication.
- **Rate Limiting**: No rate limiting is implemented. Consider adding throttling at the API Gateway level.
- **Reject Invalid Signatures**: The current implementation logs signature failures but still processes events. For stricter security, modify the code to return a 401/403 error for invalid signatures.

## Project Structure

```
tmi-webhook-example/
├── lambda_function.py   # Main Lambda handler
├── requirements.txt     # Python dependencies (none for this example)
└── README.md           # This file
```

## License

This is example code provided as-is for demonstration purposes.

## References

- [TMI Webhook Integration Documentation](https://github.com/ericfitz/tmi/wiki/Webhook-Integration)
- [AWS Lambda Documentation](https://docs.aws.amazon.com/lambda/)
- [API Gateway Documentation](https://docs.aws.amazon.com/apigateway/)
