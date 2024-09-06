import azure.functions as func
import logging
import urllib.request
import json
import os
import ssl

# Helper function to allow self-signed HTTPS certificates
def allowSelfSignedHttps(allowed):
    # Bypass server certificate verification
    if allowed and not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
        ssl._create_default_https_context = ssl._create_unverified_context

# Enable self-signed HTTPS (if needed)
allowSelfSignedHttps(True)

# Define your Azure Function App
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="yukesh_function_app")
def yukesh_function_app(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    # Get the input data from the request body
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            "Invalid input data. Ensure the input is in the correct JSON format.",
            status_code=400
        )

    # Ensure input_data exists in the request
    input_data = req_body.get("input_data")
    if not input_data:
        return func.HttpResponse(
            "Missing input_data in request body.",
            status_code=400
        )

    # Replace with the API key for the Azure ML endpoint
    api_key = os.getenv('API_KEY', '')  # Fetch from environment variable
    if not api_key:
        return func.HttpResponse(
            "API key not found. Please set the API_KEY environment variable.",
            status_code=500
        )

    # Set the URL for the Azure ML endpoint
    url = 'https://credit-endpoint-1-64baceca.eastus.inference.ml.azure.com/score'

    # Prepare the request data
    data = {
        "input_data": input_data
    }

    # Convert data to JSON and encode it
    body = str.encode(json.dumps(data))

    # Set headers for the request
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + api_key
    }

    # Make the HTTP request to the Azure ML endpoint
    try:
        req_ml = urllib.request.Request(url, body, headers)
        response = urllib.request.urlopen(req_ml)
        result = response.read().decode('utf-8')

        # Parse the result (assuming the result is a JSON object with a "predictions" field)
        result_json = json.loads(result)
        predicted_value = result_json.get("predictions", [None])[0]  # Assuming the predicted value is the first element

        if predicted_value is None:
            return func.HttpResponse(
                "Prediction failed. No prediction value returned.",
                status_code=500
            )

        # Return the predicted value
        return func.HttpResponse(f"Predicted value: {predicted_value}", status_code=200)

    except urllib.error.HTTPError as error:
        error_details = f"The request failed with status code: {error.code}\n{error.info()}\n{error.read().decode('utf8', 'ignore')}"
        logging.error(error_details)
        return func.HttpResponse(
            error_details,
            status_code=error.code
        )
