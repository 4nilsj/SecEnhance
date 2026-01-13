from typing import Dict, Any, Optional
from graphql_scanner.core.client import GraphQLClient

INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
"""

def fetch_schema(client: GraphQLClient) -> Optional[Dict[str, Any]]:
    """
    Tries to fetch the GraphQL schema using introspection.
    
    Args:
        client: The initialized GraphQLClient.
        
    Returns:
        The schema JSON dict if successful, None otherwise.
    """
    try:
        result = client.query(INTROSPECTION_QUERY)
        if result.get("errors"):
            print("Introspection query returned errors.")
            return None
        return result.get("data")
    except Exception as e:
        print(f"Failed to fetch schema: {e}")
        return None
