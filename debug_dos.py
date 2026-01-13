
from graphql_scanner.core.client import GraphQLClient
from graphql_scanner.scanner.dos import check_batch_queries

client = GraphQLClient("http://127.0.0.1:5020/graphql", cookies="auth=secret_token")
print("Check batch queries:")
res = check_batch_queries(client)
print(res)
