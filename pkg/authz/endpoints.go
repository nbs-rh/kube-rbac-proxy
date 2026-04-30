/*
Copyright 2022 the kube-rbac-proxy maintainers. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Authorization config supports Format1 (top-level rewrites and resourceAttributes) and
// Format2 (path-scoped endpoints with per-method resource rules). This file implements
// Format2 matching and attribute construction; Format1 is handled in pkg/proxy.
//
// Format1 example (YAML under authorization:):
//
//	authorization:
//	  rewrites:
//	    byQueryParameter:
//	      name: "namespace"
//	  resourceAttributes:
//	    apiVersion: v1
//	    resource: namespace
//	    subresource: metrics
//	    namespace: "{{ .Value }}"
//
// Format2 example:
//
//	authorization:
//	  endpoints:
//	    - path: /api/v1/evaluations/jobs/*/events
//	      mappings:
//	        - methods: [post]
//	          resources:
//	            - rewrites:
//	                byHttpHeader:
//	                  name: X-Tenant
//	              resourceAttributes:
//	                namespace: "{{.FromHeader}}"
//	                apiGroup: trustyai.opendatahub.io
//	                resource: status-events
//	                verb: create
//
// A single config may include both Format1 and Format2; see EndpointAttributesFromRequest
// and pkg/proxy for how requests choose between them.

package authz

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"path"
	"strings"
	"text/template"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// ErrEndpointMethodNotAllowed is returned by EndpointAttributesFromRequest when the request
// path matches a Format2 endpoint but no mapping lists the request's HTTP method. Callers
// (e.g. filters.WithAuthorization) may map this to HTTP 403 Forbidden.
var ErrEndpointMethodNotAllowed = errors.New("HTTP method not allowed for matched authorization endpoint")

// Endpoint describes path-scoped SAR mappings (Format2).
type Endpoint struct {
	Path      string            `json:"path,omitempty"`
	Mappings  []EndpointMapping `json:"mappings,omitempty"`
	PathParts []string          `json:"-"`
}

// EndpointMapping selects resource rules by HTTP method.
type EndpointMapping struct {
	Methods   []string               `json:"methods,omitempty"`
	Resources []EndpointResourceRule `json:"resources,omitempty"`
}

// EndpointResourceRule is one SAR to evaluate for a matched request.
type EndpointResourceRule struct {
	Rewrites           SubjectAccessReviewRewrites `json:"rewrites,omitempty"`
	ResourceAttributes ResourceAttributes          `json:"resourceAttributes,omitempty"`
}

// TemplateData is passed to text/template when expanding resourceAttributes in Format2 endpoint rules.
// Value is set to FromHeader or FromQueryString when those rewrites are populated (supports {{ .Value }} like Format1).
type TemplateData struct {
	Value           string
	FromHeader      string
	FromQueryString string
	FromMethod      string
}

// PrepareEndpoints must be called exactly once after building or unmarshaling a Config and
// before any Format2 endpoint matching. It populates Endpoint.PathParts from Endpoint.Path
// (via prepareEndpointPatterns) so matchEndpoint can run without splitting paths per request.
// The main binary calls this from Complete after parseAuthorizationConfigFile; tests and any
// library user that constructs Config with non-empty Endpoints must call it too. Omitting
// PrepareEndpoints leaves PathParts nil and endpoint patterns never match.
func (c *Config) PrepareEndpoints() {
	c.prepareEndpointPatterns()
}

// prepareEndpointPatterns sets PathParts for each entry in c.Endpoints. It exists only to
// implement PrepareEndpoints and must not be called from request handlers or tests; call
// PrepareEndpoints on the Config instead.
func (c *Config) prepareEndpointPatterns() {
	if c == nil {
		return
	}
	for i := range c.Endpoints {
		c.Endpoints[i].PathParts = strings.Split(c.Endpoints[i].Path, "/")
	}
}

// MatchEndpoint reports whether requestPath matches the configured endpoint pattern.
// requestPath is cleaned with path.Clean (collapse duplicate slashes, ".", "..", trailing slash)
// before splitting. Matching is exact by segment count against endpoint.Path (after PrepareEndpoints).
// A pattern segment "*" matches exactly one request segment; it does not match zero or multiple trailing segments.
func MatchEndpoint(requestPath string, endpoint Endpoint) bool {
	return matchEndpoint(requestPath, endpoint)
}

func matchEndpoint(requestPath string, endpoint Endpoint) bool {
	patternParts := endpoint.PathParts
	if len(patternParts) == 0 {
		return false
	}
	if requestPath == "" {
		requestPath = "/"
	}
	requestPath = path.Clean(requestPath)
	endpointParts := strings.Split(requestPath, "/")
	if len(endpointParts) != len(patternParts) {
		return false
	}
	for i, part := range patternParts {
		if part == "*" {
			continue
		}
		if endpointParts[i] != part {
			return false
		}
	}
	return true
}

func matchMethods(fromRequest string, fromConfig []string) bool {
	if len(fromConfig) == 0 {
		return false
	}
	m := strings.ToLower(fromRequest)
	for _, c := range fromConfig {
		if strings.ToLower(c) == m {
			return true
		}
	}
	return false
}

// ValidateAuthorizationConfig checks authorization config for inconsistencies that would
// otherwise fail silently at runtime. It returns an error if any Format2 endpoint mapping
// has an empty methods list (YAML "methods: []" or omitted methods).
func ValidateAuthorizationConfig(c *Config) error {
	if c == nil {
		return nil
	}
	for index, endpoint := range c.Endpoints {
		for mappingIndex, mapping := range endpoint.Mappings {
			if len(mapping.Methods) == 0 {
				return fmt.Errorf("authorization.endpoints[%d] (path %q): mappings[%d] must specify a non-empty methods list", index, endpoint.Path, mappingIndex)
			}
		}
	}
	return nil
}

// HTTPToKubeVerb maps an HTTP method to a Kubernetes API verb.
func HTTPToKubeVerb(httpVerb string) string {
	switch httpVerb {
	case http.MethodGet:
		return "get"
	case http.MethodPost:
		return "create"
	case http.MethodPut:
		return "update"
	case http.MethodDelete:
		return "delete"
	case http.MethodPatch:
		return "patch"
	case http.MethodOptions:
		return "options"
	case http.MethodHead:
		return "head"
	default:
		return ""
	}
}

func applyEndpointFieldTemplate(templateString string, values TemplateData) (string, error) {
	if templateString == "" {
		return "", nil
	}
	tmpl, err := template.New("endpointField").Parse(templateString)
	if err != nil {
		return "", fmt.Errorf("parse template %q: %w", templateString, err)
	}
	out := bytes.NewBuffer(nil)
	if err := tmpl.Execute(out, values); err != nil {
		return "", fmt.Errorf("execute template %q: %w", templateString, err)
	}
	return out.String(), nil
}

func expandEndpointResourceField(fieldName, templateString string, templateData TemplateData) (string, error) {
	s, err := applyEndpointFieldTemplate(templateString, templateData)
	if err != nil {
		return "", fmt.Errorf("resourceAttributes.%s: %w", fieldName, err)
	}
	return s, nil
}

// rulesForEndpointMethod returns the resource rules from the first mapping that accepts
// request.Method. The second return value is false when the endpoint path matched but no
// mapping listed the HTTP method (caller should treat as method not allowed for that path).
func rulesForEndpointMethod(request *http.Request, endpoint Endpoint) ([]EndpointResourceRule, bool) {
	for _, mapping := range endpoint.Mappings {
		if matchMethods(request.Method, mapping.Methods) {
			return mapping.Resources, true
		}
	}
	return nil, false
}

// EndpointAttributesFromRequest derives SAR attributes from authorization.endpoints (Format2).
// If the request path matches any endpoint entry, matched is true and Format1 top-level
// resourceAttributes/rewrites must not be used for that request (even when attrs is empty or err is set).
// If the path matches but no mapping accepts the request HTTP method, it returns matched==true
// and err==ErrEndpointMethodNotAllowed (use errors.Is).
func EndpointAttributesFromRequest(userInfo user.Info, request *http.Request, cfg *Config) (attrs []authorizer.Attributes, matched bool, err error) {
	if cfg == nil || len(cfg.Endpoints) == 0 {
		return nil, false, nil
	}
	for _, endpoint := range cfg.Endpoints {
		if !matchEndpoint(request.URL.Path, endpoint) {
			continue
		}
		rules, methodOK := rulesForEndpointMethod(request, endpoint)
		if !methodOK {
			return nil, true, ErrEndpointMethodNotAllowed
		}
		attrs, err := attributesFromEndpointResourceRules(userInfo, request, rules)
		return attrs, true, err
	}
	return nil, false, nil
}

func attributesFromEndpointResourceRules(u user.Info, r *http.Request, rules []EndpointResourceRule) ([]authorizer.Attributes, error) {
	var out []authorizer.Attributes
	for _, rule := range rules {
		td := TemplateData{FromMethod: HTTPToKubeVerb(r.Method)}

		if rule.Rewrites.ByHTTPHeader != nil && rule.Rewrites.ByHTTPHeader.Name != "" {
			headerValue := r.Header.Get(rule.Rewrites.ByHTTPHeader.Name)
			if headerValue == "" {
				return nil, fmt.Errorf("required header %q is missing", rule.Rewrites.ByHTTPHeader.Name)
			}
			td.FromHeader = headerValue
		}
		queryParamName := rewriteQueryParamName(&rule.Rewrites)
		if queryParamName != "" {
			vs, ok := r.URL.Query()[queryParamName]
			if !ok || len(vs) == 0 {
				return nil, fmt.Errorf("required query parameter %q is missing", queryParamName)
			}
			td.FromQueryString = vs[0]
		}
		if td.FromHeader != "" {
			td.Value = td.FromHeader
		} else if td.FromQueryString != "" {
			td.Value = td.FromQueryString
		}

		resAttrs := rule.ResourceAttributes
		verb, err := expandEndpointResourceField("verb", resAttrs.Verb, td)
		if err != nil {
			return nil, err
		}
		if verb == "" {
			verb = td.FromMethod
		}

		ns, err := expandEndpointResourceField("namespace", resAttrs.Namespace, td)
		if err != nil {
			return nil, err
		}
		group, err := expandEndpointResourceField("apiGroup", resAttrs.APIGroup, td)
		if err != nil {
			return nil, err
		}
		version, err := expandEndpointResourceField("apiVersion", resAttrs.APIVersion, td)
		if err != nil {
			return nil, err
		}
		resource, err := expandEndpointResourceField("resource", resAttrs.Resource, td)
		if err != nil {
			return nil, err
		}
		subresource, err := expandEndpointResourceField("subresource", resAttrs.Subresource, td)
		if err != nil {
			return nil, err
		}
		name, err := expandEndpointResourceField("name", resAttrs.Name, td)
		if err != nil {
			return nil, err
		}

		out = append(out, authorizer.AttributesRecord{
			User:            u,
			Verb:            verb,
			Namespace:       ns,
			APIGroup:        group,
			APIVersion:      version,
			Resource:        resource,
			Subresource:     subresource,
			Name:            name,
			ResourceRequest: true,
		})
	}
	return out, nil
}

func rewriteQueryParamName(r *SubjectAccessReviewRewrites) string {
	if r.ByQueryParameter != nil && r.ByQueryParameter.Name != "" {
		return r.ByQueryParameter.Name
	}
	return ""
}

// CollectRewriteParams gathers rewrite values for Format1 authorization using the same
// header and query keys as SubjectAccessReviewRewrites.
func CollectRewriteParams(r *http.Request, rewrites *SubjectAccessReviewRewrites) []string {
	if rewrites == nil {
		return nil
	}
	var params []string
	if rewrites.ByQueryParameter != nil && rewrites.ByQueryParameter.Name != "" {
		if ps, ok := r.URL.Query()[rewrites.ByQueryParameter.Name]; ok {
			params = append(params, ps...)
		}
	}
	if rewrites.ByHTTPHeader != nil && rewrites.ByHTTPHeader.Name != "" {
		mimeHeader := textproto.MIMEHeader(r.Header)
		mimeKey := textproto.CanonicalMIMEHeaderKey(rewrites.ByHTTPHeader.Name)
		if ps, ok := mimeHeader[mimeKey]; ok {
			params = append(params, ps...)
		}
	}
	return params
}
