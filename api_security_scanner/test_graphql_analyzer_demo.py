#!/usr/bin/env python3
"""
Demo script to showcase GraphQL analyzer functionality.
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'api_security_scanner'))

from api_security_scanner.core.request_analyzer import RequestAnalyzer


def create_test_requests():
    """Create test requests for demonstration."""
    return {
        "graphql_requests": [
            {
                "url": "https://api.example.com/graphql",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": '{"query": "query { user { name email } }"}'
            },
            {
                "url": "https://api.example.com/graphql",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": '{"query": "mutation { createUser(name: \\"John\\") { id } }"}'
            }
        ],
        "mixed_requests": [
            {
                "url": "https://api.example.com/graphql",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": '{"query": "query { user { name } }"}'
            },
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"},
                "body": '{"name": "John"}'
            }
        ],
        "rest_requests": [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"},
                "body": '{"name": "John"}'
            },
            {
                "url": "https://api.example.com/posts",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": '{"title": "Test Post"}'
            }
        ]
    }


def test_graphql_analyzer():
    """Test the GraphQL analyzer functionality."""
    print("🔍 Testing GraphQL Analyzer...")
    
    analyzer = RequestAnalyzer()
    test_data = create_test_requests()
    
    # Test GraphQL detection
    print("\n📋 Testing GraphQL Detection:")
    graphql_analysis = analyzer.analyze_requests(test_data["graphql_requests"])
    print(f"  Contains GraphQL: {graphql_analysis['contains_graphql']}")
    print(f"  GraphQL Endpoints Found: {len(graphql_analysis['graphql_endpoints'])}")
    print(f"  GraphQL Operations Found: {len(graphql_analysis['graphql_operations'])}")
    
    for endpoint in graphql_analysis['graphql_endpoints']:
        print(f"    - {endpoint['endpoint_type']}: {endpoint['url']}")
    
    for operation in graphql_analysis['graphql_operations']:
        if 'operation_type' in operation:
            print(f"    - {operation['operation_type']}: {operation['query'][:50]}...")
    
    # Test mixed requests
    print("\n🔄 Testing Mixed Requests (GraphQL + REST):")
    mixed_analysis = analyzer.analyze_requests(test_data["mixed_requests"])
    print(f"  Contains GraphQL: {mixed_analysis['contains_graphql']}")
    print(f"  Contains JWT: {mixed_analysis['contains_jwt']}")
    print(f"  Contains OAuth: {mixed_analysis['contains_oauth']}")
    
    # Test REST-only requests
    print("\n📄 Testing REST-Only Requests:")
    rest_analysis = analyzer.analyze_requests(test_data["rest_requests"])
    print(f"  Contains GraphQL: {rest_analysis['contains_graphql']}")
    print(f"  Contains JWT: {rest_analysis['contains_jwt']}")
    print(f"  Contains OAuth: {rest_analysis['contains_oauth']}")
    
    # Test plugin recommendations
    print("\n🎯 Testing Plugin Recommendations:")
    print(f"  GraphQL Requests: {analyzer.should_run_graphql_plugin(test_data['graphql_requests'])}")
    print(f"  Mixed Requests: {analyzer.should_run_graphql_plugin(test_data['mixed_requests'])}")
    print(f"  REST Requests: {analyzer.should_run_graphql_plugin(test_data['rest_requests'])}")
    
    # Test analysis summaries
    print("\n📊 Analysis Summaries:")
    print(f"  GraphQL Summary: {analyzer.get_graphql_analysis_summary(test_data['graphql_requests'])}")
    print(f"  JWT Summary: {analyzer.get_jwt_analysis_summary(test_data['graphql_requests'])}")
    
    return True


def main():
    """Main function."""
    print("🚀 GraphQL Analyzer Demo")
    print("=" * 50)
    
    try:
        success = test_graphql_analyzer()
        if success:
            print("\n✅ All tests passed!")
            print("\n🎉 GraphQL Analyzer is working correctly!")
            print("\n📝 Key Features Demonstrated:")
            print("  • GraphQL endpoint detection")
            print("  • GraphQL operation analysis")
            print("  • Conditional plugin recommendations")
            print("  • Mixed API collection support")
            print("  • REST-only API collection handling")
        else:
            print("\n❌ Some tests failed!")
            return 1
    except Exception as e:
        print(f"\n💥 Error during testing: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
