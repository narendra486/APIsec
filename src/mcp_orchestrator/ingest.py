"""
Ingest Module - Parse various API descriptors and raw HTTP inputs
Supports: OpenAPI/Swagger, WSDL, GraphQL SDL, HAR, cURL, raw HTTP
"""

import json

try:
    import yaml
except ImportError:
    import json as yaml  # Fallback
from typing import Optional
from urllib.parse import urlparse
import shlex

from .models import (
    IngestResult,
    EndpointInfo,
    AuthFlow,
    AuthType,
    AuthEndpoints,
)


class OpenAPIParser:
    """Parse OpenAPI/Swagger v2 and v3 specifications"""

    @staticmethod
    def parse(content: str | dict) -> IngestResult:
        """Parse OpenAPI spec from string or dict"""
        try:
            if isinstance(content, str):
                try:
                    spec = json.loads(content)
                except json.JSONDecodeError:
                    spec = yaml.safe_load(content)
            else:
                spec = content

            # Determine version
            version = spec.get("openapi") or spec.get("swagger", "")
            is_v3 = version.startswith("3.")

            endpoints: list[EndpointInfo] = []
            auth_flows: list[AuthFlow] = []

            # Extract base path
            base_path = ""
            if not is_v3:
                base_path = spec.get("basePath", "")
            else:
                servers = spec.get("servers", [])
                if servers:
                    base_path = servers[0].get("url", "")

            # Extract paths/endpoints
            paths = spec.get("paths", {})
            for path, path_item in paths.items():
                full_path = f"{base_path}{path}"

                for method in ["get", "post", "put", "patch", "delete", "options", "head"]:
                    if method in path_item:
                        operation = path_item[method]

                        endpoint = EndpointInfo(
                            path=full_path,
                            method=method.upper(),
                            summary=operation.get("summary"),
                            operation_id=operation.get("operationId"),
                            tags=operation.get("tags", []),
                            parameters=operation.get("parameters", []),
                            request_body=operation.get("requestBody") if is_v3 else None,
                            responses=operation.get("responses", {}),
                            security=operation.get("security", []),
                        )
                        endpoints.append(endpoint)

            # Extract security schemes / auth flows
            security_schemes = {}
            if is_v3:
                security_schemes = spec.get("components", {}).get("securitySchemes", {})
            else:
                security_schemes = spec.get("securityDefinitions", {})

            for scheme_name, scheme in security_schemes.items():
                auth_type_map = {
                    "oauth2": AuthType.OAUTH2,
                    "apiKey": AuthType.APIKEY,
                    "http": AuthType.BASIC,  # simplified
                }

                scheme_type = scheme.get("type", "")
                auth_type = auth_type_map.get(scheme_type, AuthType.CUSTOM)

                endpoints_dict: dict[str, Optional[str]] = {
                    "authorize": None,
                    "token": None,
                    "refresh": None,
                }

                if auth_type == AuthType.OAUTH2:
                    if is_v3:
                        flows = scheme.get("flows", {})
                        for flow_type, flow_data in flows.items():
                            endpoints_dict["authorize"] = flow_data.get("authorizationUrl")
                            endpoints_dict["token"] = flow_data.get("tokenUrl")
                            endpoints_dict["refresh"] = flow_data.get("refreshUrl")
                    else:
                        endpoints_dict["authorize"] = scheme.get("authorizationUrl")
                        endpoints_dict["token"] = scheme.get("tokenUrl")

                auth_flow = AuthFlow(
                    type=auth_type,
                    endpoints=AuthEndpoints(**endpoints_dict),
                    parameters={"scheme_name": scheme_name},
                    scopes=(
                        list(scheme.get("scopes", {}).keys())
                        if auth_type == AuthType.OAUTH2
                        else None
                    ),
                    metadata=scheme,
                )
                auth_flows.append(auth_flow)

            return IngestResult(
                success=True,
                descriptor_type=f"openapi_{version}",
                endpoints=endpoints,
                auth_flows=auth_flows,
                errors=[],
                warnings=[],
                metadata={
                    "title": spec.get("info", {}).get("title"),
                    "version": spec.get("info", {}).get("version"),
                    "description": spec.get("info", {}).get("description"),
                },
            )

        except Exception as e:
            return IngestResult(
                success=False,
                descriptor_type="openapi",
                endpoints=[],
                auth_flows=[],
                errors=[f"Failed to parse OpenAPI spec: {str(e)}"],
                warnings=[],
                metadata={},
            )


class GraphQLParser:
    """Parse GraphQL SDL/introspection results"""

    @staticmethod
    def parse(content: str | dict, endpoint: str = "/graphql") -> IngestResult:
        """Parse GraphQL schema or introspection query result"""
        try:
            endpoints: list[EndpointInfo] = []

            # If it's introspection result
            if isinstance(content, dict) and "data" in content:
                schema = content["data"].get("__schema", {})
                query_type = schema.get("queryType", {}).get("name")
                mutation_type = schema.get("mutationType", {}).get("name")

                # Create endpoint entries for queries and mutations
                if query_type:
                    endpoints.append(
                        EndpointInfo(
                            path=endpoint,
                            method="POST",
                            summary=f"GraphQL Query ({query_type})",
                            operation_id="graphql_query",
                            tags=["graphql", "query"],
                            parameters=[],
                            request_body={"type": "application/json"},
                            responses={},
                            security=[],
                        )
                    )

                if mutation_type:
                    endpoints.append(
                        EndpointInfo(
                            path=endpoint,
                            method="POST",
                            summary=f"GraphQL Mutation ({mutation_type})",
                            operation_id="graphql_mutation",
                            tags=["graphql", "mutation"],
                            parameters=[],
                            request_body={"type": "application/json"},
                            responses={},
                            security=[],
                        )
                    )

            else:
                # SDL schema - create generic endpoint
                endpoints.append(
                    EndpointInfo(
                        path=endpoint,
                        method="POST",
                        summary="GraphQL Endpoint",
                        operation_id="graphql",
                        tags=["graphql"],
                        parameters=[],
                        request_body={"type": "application/json"},
                        responses={},
                        security=[],
                    )
                )

            return IngestResult(
                success=True,
                descriptor_type="graphql",
                endpoints=endpoints,
                auth_flows=[],
                errors=[],
                warnings=[],
                metadata={"endpoint": endpoint, "schema": content},
            )

        except Exception as e:
            return IngestResult(
                success=False,
                descriptor_type="graphql",
                endpoints=[],
                auth_flows=[],
                errors=[f"Failed to parse GraphQL schema: {str(e)}"],
                warnings=[],
                metadata={},
            )


class HARParser:
    """Parse HTTP Archive (HAR) files"""

    @staticmethod
    def parse(content: str | dict) -> IngestResult:
        """Parse HAR file"""
        try:
            if isinstance(content, str):
                har_data = json.loads(content)
            else:
                har_data = content

            entries = har_data.get("log", {}).get("entries", [])
            endpoints: list[EndpointInfo] = []
            seen_paths: set[str] = set()

            for entry in entries:
                request = entry.get("request", {})
                method = request.get("method", "GET")
                url = request.get("url", "")

                parsed = urlparse(url)
                path = parsed.path or "/"

                # Deduplicate by method + path
                key = f"{method}:{path}"
                if key not in seen_paths:
                    seen_paths.add(key)

                    # Extract headers as parameters
                    headers = request.get("headers", [])
                    params = [{"name": h.get("name"), "in": "header"} for h in headers]

                    # Extract query params
                    query_string = request.get("queryString", [])
                    params.extend([{"name": q.get("name"), "in": "query"} for q in query_string])

                    endpoints.append(
                        EndpointInfo(
                            path=path,
                            method=method,
                            summary=f"HAR captured: {method} {path}",
                            operation_id=None,
                            tags=["har"],
                            parameters=params,
                            request_body=request.get("postData"),
                            responses={},
                            security=[],
                        )
                    )

            return IngestResult(
                success=True,
                descriptor_type="har",
                endpoints=endpoints,
                auth_flows=[],
                errors=[],
                warnings=[],
                metadata={"total_entries": len(entries), "unique_endpoints": len(endpoints)},
            )

        except Exception as e:
            return IngestResult(
                success=False,
                descriptor_type="har",
                endpoints=[],
                auth_flows=[],
                errors=[f"Failed to parse HAR: {str(e)}"],
                warnings=[],
                metadata={},
            )


class CurlParser:
    """Parse cURL commands into structured requests"""

    @staticmethod
    def parse(curl_command: str) -> IngestResult:
        """Parse a cURL command"""
        try:
            # Remove 'curl' prefix and clean up
            curl_command = curl_command.strip()
            if curl_command.startswith("curl "):
                curl_command = curl_command[5:]

            # Use shlex to safely parse shell arguments
            parts = shlex.split(curl_command)

            method = "GET"
            url = ""
            headers: dict[str, str] = {}
            body: Optional[str] = None

            i = 0
            while i < len(parts):
                part = parts[i]

                if part in ["-X", "--request"]:
                    method = parts[i + 1].upper()
                    i += 2
                elif part in ["-H", "--header"]:
                    header = parts[i + 1]
                    if ":" in header:
                        key, value = header.split(":", 1)
                        headers[key.strip()] = value.strip()
                    i += 2
                elif part in ["-d", "--data", "--data-raw", "--data-binary"]:
                    body = parts[i + 1]
                    if method == "GET":
                        method = "POST"
                    i += 2
                elif not part.startswith("-"):
                    # Assume it's the URL
                    url = part
                    i += 1
                else:
                    i += 1

            if not url:
                return IngestResult(
                    success=False,
                    descriptor_type="curl",
                    endpoints=[],
                    auth_flows=[],
                    errors=["No URL found in cURL command"],
                    warnings=[],
                    metadata={},
                )

            parsed_url = urlparse(url)
            path = parsed_url.path or "/"

            endpoint = EndpointInfo(
                path=path,
                method=method,
                summary=f"cURL: {method} {path}",
                operation_id=None,
                tags=["curl"],
                parameters=[],
                request_body={"content": body} if body else None,
                responses={},
                security=[],
            )

            return IngestResult(
                success=True,
                descriptor_type="curl",
                endpoints=[endpoint],
                auth_flows=[],
                errors=[],
                warnings=[],
                metadata={
                    "url": url,
                    "method": method,
                    "headers": headers,
                    "body": body,
                },
            )

        except Exception as e:
            return IngestResult(
                success=False,
                descriptor_type="curl",
                endpoints=[],
                auth_flows=[],
                errors=[f"Failed to parse cURL: {str(e)}"],
                warnings=[],
                metadata={},
            )


class RawHTTPParser:
    """Parse raw HTTP requests"""

    @staticmethod
    def parse(raw_request: str) -> IngestResult:
        """Parse raw HTTP request string"""
        try:
            lines = raw_request.strip().split("\n")
            if not lines:
                raise ValueError("Empty request")

            # Parse request line
            request_line = lines[0].strip()
            parts = request_line.split()
            if len(parts) < 2:
                raise ValueError("Invalid request line")

            method = parts[0].upper()
            path = parts[1]

            # Parse headers
            headers: dict[str, str] = {}
            body_start = 1
            for i in range(1, len(lines)):
                line = lines[i].strip()
                if not line:
                    body_start = i + 1
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()

            # Parse body
            body = "\n".join(lines[body_start:]).strip() if body_start < len(lines) else None

            endpoint = EndpointInfo(
                path=path,
                method=method,
                summary=f"Raw HTTP: {method} {path}",
                operation_id=None,
                tags=["raw"],
                parameters=[],
                request_body={"content": body} if body else None,
                responses={},
                security=[],
            )

            return IngestResult(
                success=True,
                descriptor_type="raw",
                endpoints=[endpoint],
                auth_flows=[],
                errors=[],
                warnings=[],
                metadata={
                    "method": method,
                    "path": path,
                    "headers": headers,
                    "body": body,
                },
            )

        except Exception as e:
            return IngestResult(
                success=False,
                descriptor_type="raw",
                endpoints=[],
                auth_flows=[],
                errors=[f"Failed to parse raw HTTP: {str(e)}"],
                warnings=[],
                metadata={},
            )


class IngestOrchestrator:
    """Main ingestion orchestrator - auto-detects format and delegates"""

    @staticmethod
    def ingest(content: str | dict, descriptor_type: Optional[str] = None) -> IngestResult:
        """Auto-detect and parse API descriptor or request"""

        # If type specified, use appropriate parser
        if descriptor_type:
            parsers = {
                "openapi": OpenAPIParser.parse,
                "swagger": OpenAPIParser.parse,
                "graphql": GraphQLParser.parse,
                "har": HARParser.parse,
                "curl": CurlParser.parse,
                "raw": RawHTTPParser.parse,
            }

            parser = parsers.get(descriptor_type.lower())
            if parser:
                return parser(content)

        # Auto-detection
        if isinstance(content, dict):
            # Check for OpenAPI/Swagger
            if "openapi" in content or "swagger" in content:
                return OpenAPIParser.parse(content)

            # Check for GraphQL introspection
            if "data" in content and "__schema" in content.get("data", {}):
                return GraphQLParser.parse(content)

            # Check for HAR
            if "log" in content and "entries" in content.get("log", {}):
                return HARParser.parse(content)

        elif isinstance(content, str):
            # Check for cURL
            if content.strip().startswith("curl "):
                return CurlParser.parse(content)

            # Try JSON/YAML parsing
            try:
                parsed = json.loads(content)
                return IngestOrchestrator.ingest(parsed)
            except json.JSONDecodeError:
                try:
                    parsed = yaml.safe_load(content)
                    return IngestOrchestrator.ingest(parsed)
                except yaml.YAMLError:
                    pass

            # Try raw HTTP
            if content.strip().split("\n")[0].split()[0].upper() in [
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
                "HEAD",
            ]:
                return RawHTTPParser.parse(content)

        return IngestResult(
            success=False,
            descriptor_type="unknown",
            endpoints=[],
            auth_flows=[],
            errors=["Could not auto-detect format. Please specify descriptor_type."],
            warnings=[],
            metadata={},
        )
