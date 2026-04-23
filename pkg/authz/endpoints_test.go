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

package authz

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func testUser(name string) user.Info {
	return &user.DefaultInfo{Name: name}
}

func TestMatchEndpoint(t *testing.T) {
	cases := []struct {
		pattern       string
		path          string
		expectedMatch bool
	}{
		{"/api/v1/jobs", "/api/v1/jobsabc", false},
		{"/api/v1/jobs", "/api/v1/jobs/123", true},
		{"/api/v1/jobs/*", "/api/v1/jobs", true},
		{"/api/v1/jobs/*", "/api/v1/jobs/123", true},
		{"/api/v1/jobs/*", "/api/v1/jobs/123/details", true},
		{"/api/*/jobs/*", "/api/v2/jobs/abc", true},
		{"/api/*/jobs/*", "/api/v2/users/123", false},
		{"/api/v1/evaluations/jobs/*/events", "/api/v1/evaluations/jobs", false},
		{"/api/v1/evaluations/jobs/*/events", "/api/v1/evaluations/jobs/j1/events", true},
	}

	for _, c := range cases {
		ep := Endpoint{Path: c.pattern, PathParts: strings.Split(c.pattern, "/")}
		match := MatchEndpoint(c.path, ep)
		if match != c.expectedMatch {
			t.Errorf("MatchEndpoint(%q, pattern %q) = %v, want %v", c.path, c.pattern, match, c.expectedMatch)
		}
	}
}

func TestHTTPToKubeVerb(t *testing.T) {
	if got, want := HTTPToKubeVerb(http.MethodPost), "create"; got != want {
		t.Fatalf("HTTPToKubeVerb(POST) = %q, want %q", got, want)
	}
}

func TestEndpointAttributesFromRequest_StatusEvents(t *testing.T) {
	cfg := &Config{
		Endpoints: []Endpoint{{
			Path: "/api/v1/evaluations/jobs/*/events",
			Mappings: []EndpointMapping{{
				Methods: []string{"post"},
				Resources: []EndpointResourceRule{{
					Rewrites: SubjectAccessReviewRewrites{
						ByHTTPHeader: &HTTPHeaderRewriteConfig{Name: "X-Tenant"},
					},
					ResourceAttributes: ResourceAttributes{
						Namespace: "{{.FromHeader}}",
						APIGroup:  "trustyai.opendatahub.io",
						Resource:  "status-events",
						Verb:      "create",
					},
				}},
			}},
		}},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluations/jobs/job-1/events", nil)
	req.Header.Set("X-Tenant", "tenant-ns")

	attrs, matched, err := EndpointAttributesFromRequest(testUser("u"), req, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected path to match endpoints")
	}
	if len(attrs) != 1 {
		t.Fatalf("len(attrs)=%d, want 1", len(attrs))
	}
	rec := attrs[0].(authorizer.AttributesRecord)
	if rec.Namespace != "tenant-ns" || rec.APIGroup != "trustyai.opendatahub.io" || rec.Resource != "status-events" || rec.Verb != "create" {
		t.Fatalf("unexpected record: %#v", rec)
	}
}

func TestEndpointAttributesFromRequest_MissingHeader(t *testing.T) {
	cfg := &Config{
		Endpoints: []Endpoint{{
			Path: "/api/v1/evaluations/jobs/*/events",
			Mappings: []EndpointMapping{{
				Methods: []string{"post"},
				Resources: []EndpointResourceRule{{
					Rewrites: SubjectAccessReviewRewrites{
						ByHTTPHeader: &HTTPHeaderRewriteConfig{Name: "X-Tenant"},
					},
					ResourceAttributes: ResourceAttributes{Namespace: "{{.FromHeader}}", Verb: "create"},
				}},
			}},
		}},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluations/jobs/j1/events", nil)
	_, matched, err := EndpointAttributesFromRequest(testUser("u"), req, cfg)
	if !matched {
		t.Fatal("expected matched path")
	}
	if err == nil {
		t.Fatal("expected error for missing header")
	}
}

func TestEndpointAttributesFromRequest_NoMatchUsesFormat1(t *testing.T) {
	cfg := &Config{
		Endpoints: []Endpoint{{
			Path: "/api/v1/other",
			Mappings: []EndpointMapping{{
				Methods: []string{"get"},
				Resources: []EndpointResourceRule{{
					ResourceAttributes: ResourceAttributes{Resource: "should-not-use"},
				}},
			}},
		}},
		Rewrites: &SubjectAccessReviewRewrites{
			ByQueryParameter: &QueryParameterRewriteConfig{Name: "namespace"},
		},
		ResourceAttributes: &ResourceAttributes{
			Namespace:   "{{ .Value }}",
			APIVersion:  "v1",
			Resource:    "namespace",
			Subresource: "metrics",
		},
	}
	// This path does not match /api/v1/other. Format1 applies in pkg/proxy after
	// EndpointAttributesFromRequest returns matched=false. Here we only assert the latter:
	req := httptest.NewRequest(http.MethodGet, "/metrics?namespace=ns1", nil)
	attrs, matched, err := EndpointAttributesFromRequest(testUser("u"), req, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("did not expect endpoint match")
	}
	if attrs != nil {
		t.Fatalf("expected nil attrs from EndpointAttributesFromRequest, got %#v", attrs)
	}
}

func TestCollectRewriteParams(t *testing.T) {
	rw := &SubjectAccessReviewRewrites{
		ByQueryParameter: &QueryParameterRewriteConfig{Name: "ns"},
		ByHTTPHeader:     &HTTPHeaderRewriteConfig{Name: "X-Org"},
	}
	req := httptest.NewRequest(http.MethodGet, "/x?ns=a&ns=b", nil)
	req.Header.Set("X-Org", "c")
	params := CollectRewriteParams(req, rw)
	if len(params) != 3 {
		t.Fatalf("params=%v want len 3", params)
	}
}
