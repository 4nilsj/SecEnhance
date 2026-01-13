from flask import Flask, jsonify, request
from graphene import ObjectType, String, Schema, Field, Int, Interface

# 1. Define Schema

# Logic Vulnerability: Interface Leak
class Character(Interface):
    name = String()

class User(ObjectType):
    class Meta:
        interfaces = (Character, )
    name = String()

class AdminUser(ObjectType):
    class Meta:
        interfaces = (Character, )
    name = String()
    secret = String() # Hidden field only on Admin

class Query(ObjectType):
    hello = String(name=String(default_value="stranger"))
    user = Field(User, id=String())
    # Input Validation: Field taking Int
    echo_int = Int(val=Int())
    
    def resolve_hello(root, info, name):
        # Directive Fuzzing Simulation
        # If query has @internal, we might leak it in real server, here Graphene handles directives.
        # But we can check if we received it? Actually Graphene by default might error on unknown directives.
        # We will manually check request string for @admin to simulate "acceptance"
        return f"Hello {name}!"

    def resolve_user(root, info, id):
        # Simulate SQL Injection Vulnerability
        if "'" in id:
            raise Exception("SQL syntax error: syntax error at or near \"'\"")
            
        # IDOR Simulation
        if id == "1":
             return User(name="Alice (Private)")
        elif id == "2":
             return User(name="Bob")
             
        return User(name="Test User")

    def resolve_echo_int(root, info, val):
        # Input Validation: Int Limit
        if val > 2147483647: # Classic 32-bit overflow
            raise Exception("Integer Overflow: value too large for column")
        return val

class Mutation(ObjectType):
    create_user = Field(User, name=String(), id=String())
    
    def resolve_create_user(root, info, name, id):
        # Vulnerable Mutation
        if "'" in name:
             raise Exception("SQL syntax error in Mutation")
        return User(name=name, id=id)

schema = Schema(query=Query, mutation=Mutation, types=[User, AdminUser]) # Explicitly add AdminUser so it appears in introspection

app = Flask(__name__)

@app.route("/graphql", methods=["GET", "POST"])
def graphql_server():
    # Simple Authentication Check (cookie)
    auth_cookie = request.cookies.get("auth")
    if not auth_cookie:
        return jsonify({"errors": [{"message": "Unauthorized"}]}), 401

    # Hande URL Encoded (request.form) or JSON
    data = None
    if request.method == "POST":
        if "application/json" in request.headers.get("Content-Type", ""):
            data = request.get_json()
        elif "application/x-www-form-urlencoded" in request.headers.get("Content-Type", ""):
            # Simulate parsing query from form
            query = request.form.get("query")
            if query:
                data = {"query": query}
    elif request.method == "GET":
        query = request.args.get("query")
        if query:
            data = {"query": query}

    if not data:
        return jsonify({"errors": [{"message": "No data provided"}]}), 400

    # Batch Support Check
    if isinstance(data, list):
        # Allow batching
        results = []
        for item in data:
            query_string = item.get("query")
            # Execute each
            result = schema.execute(query_string)
            res_dict = {"data": result.data}
            if result.errors:
                 res_dict["errors"] = [str(e) for e in result.errors]
            results.append(res_dict)
        return jsonify(results)

    query_string = data.get("query")

    # Custom Directive Logic Simulation (Manual check as Graphene needs custom directive definition)
    if query_string and "@admin" in query_string:
        # Simulate success/acceptance of hidden directive by NOT blocking it
        # But we need Graphene to not error out "Unknown directive". 
        # So we cheat: we remove it before execution to simulate "processed", 
        # BUT we return a dummy extension saying "Admin Access Granted"
        query_string = query_string.replace("@admin", "")
        # Execution happens below, we'll append extension later if possible.
        # Actually simplest way: just return a custom success if we spot it, mocking the behavior.
        return jsonify({"data": {"hello": "Hello Admin!"}, "extensions": {"admin": True}})

    
    # Simulate Depth Limit (only for demo purposes, if depth > 5, return error)
    if query_string and query_string.count("{") > 200: # Increased limit so we don't trigger on aliases too easily
         pass # In real world, we'd block. Here we let it pass to show vulnerability.

    # Simulate Stack Trace Leakage on Syntax Error
    if query_string and "invalid syntax" in query_string:
         return jsonify({"errors": [{"message": "Syntax Error", "extensions": {"exception": {"stacktrace": ["Traceback (most recent call last)", "File \"app.py\", line 100", "ZeroDivisionError"]}}}]})

    try:
        result = schema.execute(query_string)
        response = {"data": result.data}
        if result.errors:
            response["errors"] = [str(e) for e in result.errors]
        return jsonify(response)
    except Exception as e:
        return jsonify({"errors": [{"message": str(e)}]}), 500

if __name__ == "__main__":
    app.run(port=5020)
