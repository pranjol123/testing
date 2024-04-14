from flask import *
import boto3
import json
import requests
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal
from functools import reduce

app = Flask(__name__)
app.secret_key = "0123456789"
ACCESS_KEY = "ACCESS_KEY"
SECRET_KEY = "SECRET_KEY"

# Function to check user login
def check_login(user, password, dynamodb=None):
    """
    Checks if the provided user and password match the credentials in the DynamoDB table.
    Returns the user's name if the login is successful, False otherwise.
    """
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

    table = dynamodb.Table('login')
    try:
        response = table.get_item(Key={'email': user})
        item = response.get('Item', None)
        if item and item.get('password') == password:
            return item.get('user_name')
    except ClientError as e:
        # Optionally log the error or handle it differently
        pass
    return False

# Route for the subscription page
@app.route('/subscription')
def subscription():
    """
    Retrieves the user's subscriptions from the DynamoDB table and renders the 'my_subscriptions.html' template.
    """
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('subscriptions')
    response = query_subscription_db(table)
    if 'Items' in response:
        return render_template('my_subscriptions.html', posts=response, user_name=session['username'])
    else:
        return render_template('my_subscriptions.html', posts='', user_name=session['username'])

# Route for removing a subscription
@app.route('/remove', methods=['POST'])
def remove():
    """
    Removes a subscription from the DynamoDB table and updates the 'my_subscriptions.html' template.
    """
    if request.method == 'POST':
        username = session['username']
        title = request.form['title']
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table('subscriptions')
        try:
            response = table.delete_item(
                Key={
                    'user_name': username,
                    'title': title
                },
            )
        except ClientError as e:
            if e.response['Error']['Code'] == "ConditionalCheckFailedException":
                print(e.response['Error']['Message'])
            else:
                raise
        else:
            response = query_subscription_db(table)
            if 'Items' in response:
                return render_template('my_subscriptions.html', posts=response, user_name=session['username'])
            else:
                return render_template('my_subscriptions.html', posts='', user_name=session['username'])

# Function to query the subscription database
def query_subscription_db(table):
    """
    Queries the DynamoDB table for the user's subscriptions.
    Returns the response from the query.
    """
    response = table.query(
        KeyConditionExpression=Key('user_name').eq(session['username'])
    )
    return response

# Route for the query area page
@app.route('/query_area')
def query_area():
    """
    Renders the 'query_area.html' template.
    """
    return render_template('query_area.html', user_name=session['username'], posts='')

# Route for the back button
@app.route('/back')
def back():
    """
    Renders the 'main_page.html' template.
    """
    return render_template('main_page.html', user_name=session['username'])

# Route for querying music data
@app.route('/query_music', methods=['POST'])
def query_music():
    """
    Queries the DynamoDB 'Music' table based on the provided title, year, and artist.
    Renders the 'query_area.html' template with the query results.
    """
    if request.method == 'POST':
        title = request.form['title']
        year = request.form['year']
        artist = request.form['artist']
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        try:
            table = dynamodb.Table('Music')
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                app.logger.error(f"DynamoDB error: {e}")
                return render_template('query_area.html', posts='', user_name=session['username'], error='The "Music" table does not exist in DynamoDB.')
            else:
                raise

        try:
            # Define the KeyConditionExpression and FilterExpression
            key_conditions = []
            filter_expressions = []

            if title:
                key_conditions.append(Key('title').eq(title))
                app.logger.info(f"Key condition: title = {title}")

            if year:
                filter_expressions.append(Attr('year').eq(year))
                app.logger.info(f"Filter expression: year = {year}")

            if artist:
                filter_expressions.append(Attr('artist').eq(artist))
                app.logger.info(f"Filter expression: artist = {artist}")

            # Construct the KeyConditionExpression and FilterExpression
            key_condition_expr = reduce(lambda x, y: x & y, key_conditions) if key_conditions else None
            filter_expr = reduce(lambda x, y: x & y, filter_expressions) if filter_expressions else None

            # Query the table using the constructed expressions
            if key_condition_expr and filter_expr:
                app.logger.info("Querying table with key condition and filter expression")
                response = table.query(
                    KeyConditionExpression=key_condition_expr,
                    FilterExpression=filter_expr
                )
            elif key_condition_expr:
                app.logger.info("Querying table with key condition only")
                response = table.query(
                    KeyConditionExpression=key_condition_expr
                )
            elif filter_expr:
                app.logger.info("Scanning table with filter expression")
                response = table.scan(FilterExpression=filter_expr)
            else:
                app.logger.info("No conditions provided, returning empty result")
                response = {"Items": []}  # Return empty result if no conditions provided

        except ClientError as e:
            # Handle exceptions appropriately (e.g., log the error)
            app.logger.error(f"DynamoDB error: {e}")
            return render_template('query_area.html', posts='', user_name=session['username'])

        app.logger.info(f"Query response: {response}")
        return render_template('query_area.html', posts=response.get("Items", []), user_name=session['username'])

# Route for subscribing to music
@app.route('/subscribe', methods=['POST'])
def subscribe():
    """
    Adds a new subscription to the DynamoDB 'subscriptions' table and updates the 'my_subscriptions.html' template.
    """
    if request.method == "POST":
        title = request.form['title']
        artist = request.form['artist']
        year = request.form['year']
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table('subscriptions')
        table.put_item(
            Item={
                'title': title,
                'user_name': session['username'],
                'artist': artist,
                'year': year
            })
        response = query_subscription_db(table)
        if 'Items' in response:
            return render_template('my_subscriptions.html', posts=response, user_name=session['username'])
        else:
            return render_template('query_area.html', posts='', user_name=session['username'])

# Route for logout
@app.route('/logout')
def logout():
    """
    Clears the session and renders the 'login.html' template.
    """
    session.clear()
    return render_template('login.html')

# Route for user registration
@app.route('/register_user', methods=['POST'])
def register_user():
    """
    Registers a new user in the DynamoDB 'login' table and renders the 'login.html' template.
    """
    if request.method == "POST":
        username = request.form['user']
        password = request.form['password']
        email = request.form['email']
        result = check_user(email)
        if result is True:
            dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
            table = dynamodb.Table('login')
            table.put_item(
                Item={
                    'email': email,
                    'user_name': username,
                    'password': password
                }
            )
            return render_template('login.html')
        return render_template('register.html', invalid="The email already exists")

# Route for the registration page
@app.route('/register')
def register():
    """
    Renders the 'register.html' template.
    """
    return render_template('register.html')

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    """
    Checks the user's login credentials and renders the 'main_page.html' template if successful.
    """
    if request.method == 'POST':
        username = request.form['user']
        password = request.form['password']
        result = check_login(username, password)
        app.logger.info(result)
        if (result is False):
            return render_template('login.html', invalid="email or password is invalid")
        else:
            session['username'] = result
            app.logger.info(session['username'])
            return render_template('main_page.html', user_name=result)

# Starting point of the application
@app.route('/')
def root():
    """
    Renders the 'login.html' template.
    """
    return render_template('login.html')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)