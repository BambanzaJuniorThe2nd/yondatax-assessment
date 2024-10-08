# YondaTax API

YondaTax API is a FastAPI-based application that manages digital wallets and transactions for users. It provides endpoints for user management, wallet operations, and financial transactions.

## Features

- User authentication and authorization
- Digital wallet management
- Multi-currency support
- Funds transfer between wallets
- Transaction history
- Admin operations for crediting and debiting user wallets

## Technology Stack

- Python 3.8+
- FastAPI
- MongoDB
- Redis
- Motor (asynchronous MongoDB driver)
- Pydantic for data validation
- JWT for authentication

## Installation

1. Clone the repository:
```
git clone https://github.com/BambanzaJuniorThe2nd/yondatax-assessment.git
cd yondatax-assessment
```

2. Create a virtual environment and activate it:
```
python -m venv venv
source venv/bin/activate  # On Windows, use venv/Scripts/activate
```

3. Install the required packages:
```
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the root directory and add the following variables:
```
MONGO_DETAILS=mongodb://localhost:27017
JWT_SECRET_KEY=your_secret_key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
EXCHANGE_RATE_API_KEY=your_api_key
```

## Running the Application without Docker

To run the application locally, first make sure your mongodb community server and redis are running, then execute the following command:

`uvicorn app.main:app --reload`

## Running the Application using Docker

To get the REST API service running using a docker image, follow these simple steps:

1. Clone the repository
2. Create a .env file in the server folder with the appropriate variables and values
3. At the root folder, run the build_and_run_server_image.sh bash script as follows:
`chmod +x build_and_run_docker_image.sh && ./build_and_run_docker_image.sh`

The above script will build and run a docker image of the REST API. It will also create two other image containers for Redis and mongodb community server. To avoid any conflicts with existing local instances, make sure to stop any mongodb server and/or redis services you may have running before executing the script.

## API Documentation

Once the application is running, you can access the interactive API documentation:

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Areas for improvement

- Application architecture: Due to time constraints, the separation of concerns such as business logic and data access logic could not be fully implemented. This would have made the application more scalable and maintainable.

- Funds transfer between wallets: The endpoint `{{base_url}}/wallets/{{wallet_id}}/transfer` behind this feature and functionality requires three data points in its body, namely `source_wallet_id`, `target_wallet_id`, and `amount`. The first data point is redundant, as `wallet_id` can be used to identity the source wallet.