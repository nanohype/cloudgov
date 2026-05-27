package iam

import (
	"reflect"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestBuildMinimalPermissions_Empty(t *testing.T) {
	got := BuildMinimalPermissions(nil)
	if len(got) != 0 {
		t.Errorf("expected empty output for nil input, got %v", got)
	}
	got = BuildMinimalPermissions([]cloud.Permission{})
	if len(got) != 0 {
		t.Errorf("expected empty output for empty input, got %v", got)
	}
}

func TestBuildMinimalPermissions_NoDuplicates(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:PutObject", "arn:aws:s3:::bucket/*"),
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
		perm("ec2:DescribeInstances", "*"),
	}
	got := BuildMinimalPermissions(input)
	if len(got) != 3 {
		t.Errorf("expected 3 permissions, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].Action < got[i-1].Action {
			t.Errorf("output not sorted: %q before %q", got[i-1].Action, got[i].Action)
		}
	}
}

func TestBuildMinimalPermissions_DeduplicatesSameActionAndResource(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
	}
	got := BuildMinimalPermissions(input)
	if len(got) != 1 {
		t.Errorf("expected 1 after dedup, got %d: %v", len(got), got)
	}
	if got[0].Action != "s3:GetObject" || got[0].Resource != "arn:aws:s3:::bucket/*" {
		t.Errorf("unexpected permission: %v", got[0])
	}
}

func TestBuildMinimalPermissions_SameActionDifferentResource(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:GetObject", "arn:aws:s3:::bucket-a/*"),
		perm("s3:GetObject", "arn:aws:s3:::bucket-b/*"),
	}
	got := BuildMinimalPermissions(input)
	if len(got) != 2 {
		t.Errorf("same action+different resource should both be kept, got %d", len(got))
	}
}

func TestBuildMinimalPermissions_DifferentActionSameResource(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
		perm("s3:PutObject", "arn:aws:s3:::bucket/*"),
	}
	got := BuildMinimalPermissions(input)
	if len(got) != 2 {
		t.Errorf("different action+same resource should both be kept, got %d", len(got))
	}
}

func TestBuildMinimalPermissions_SortedByAction(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:PutObject", "arn:aws:s3:::bucket/*"),
		perm("ec2:DescribeInstances", "*"),
		perm("iam:GetRole", "*"),
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
	}
	got := BuildMinimalPermissions(input)
	if len(got) != 4 {
		t.Fatalf("expected 4 permissions, got %d", len(got))
	}
	want := []string{"ec2:DescribeInstances", "iam:GetRole", "s3:GetObject", "s3:PutObject"}
	for i, w := range want {
		if got[i].Action != w {
			t.Errorf("position %d: want action %q, got %q", i, w, got[i].Action)
		}
	}
}

func TestBuildMinimalPermissions_MixedDuplicatesAndUnique(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
		perm("s3:PutObject", "arn:aws:s3:::bucket/*"),
		perm("ec2:DescribeInstances", "*"),
		perm("ec2:DescribeInstances", "*"),
	}
	got := BuildMinimalPermissions(input)
	if len(got) != 3 {
		t.Errorf("expected 3 unique permissions, got %d: %v", len(got), got)
	}
}

func TestGroupByResource_Empty(t *testing.T) {
	got := GroupByResource(nil)
	if len(got) != 0 {
		t.Errorf("expected empty map for nil input, got %v", got)
	}
	got = GroupByResource([]cloud.Permission{})
	if len(got) != 0 {
		t.Errorf("expected empty map for empty input, got %v", got)
	}
}

func TestGroupByResource_SinglePermission(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
	}
	got := GroupByResource(input)
	actions, ok := got["arn:aws:s3:::bucket/*"]
	if !ok {
		t.Fatalf("expected key %q in map, got %v", "arn:aws:s3:::bucket/*", got)
	}
	if !reflect.DeepEqual(actions, []string{"s3:GetObject"}) {
		t.Errorf("expected [s3:GetObject], got %v", actions)
	}
}

func TestGroupByResource_EmptyResourceMapsToWildcard(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:GetObject", ""),
	}
	got := GroupByResource(input)
	if _, ok := got["*"]; !ok {
		t.Errorf("empty resource should map to \"*\", got keys: %v", mapKeys(got))
	}
	if _, ok := got[""]; ok {
		t.Error("empty string should not be a key when resource is empty")
	}
}

func TestGroupByResource_GroupsMultipleActionsForSameResource(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
		perm("s3:PutObject", "arn:aws:s3:::bucket/*"),
		perm("s3:DeleteObject", "arn:aws:s3:::bucket/*"),
	}
	got := GroupByResource(input)
	if len(got) != 1 {
		t.Fatalf("expected 1 resource key, got %d: %v", len(got), got)
	}
	actions := got["arn:aws:s3:::bucket/*"]
	if len(actions) != 3 {
		t.Errorf("expected 3 actions, got %d: %v", len(actions), actions)
	}
}

func TestGroupByResource_DeduplicatesActionsWithinResource(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
		perm("s3:PutObject", "arn:aws:s3:::bucket/*"),
	}
	got := GroupByResource(input)
	actions := got["arn:aws:s3:::bucket/*"]
	if len(actions) != 2 {
		t.Errorf("expected 2 deduplicated actions, got %d: %v", len(actions), actions)
	}
}

func TestGroupByResource_ActionsSortedWithinResource(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:PutObject", "arn:aws:s3:::bucket/*"),
		perm("s3:DeleteObject", "arn:aws:s3:::bucket/*"),
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
	}
	got := GroupByResource(input)
	actions := got["arn:aws:s3:::bucket/*"]
	want := []string{"s3:DeleteObject", "s3:GetObject", "s3:PutObject"}
	if !reflect.DeepEqual(actions, want) {
		t.Errorf("actions not sorted: want %v, got %v", want, actions)
	}
}

func TestGroupByResource_MultipleResources(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:GetObject", "arn:aws:s3:::bucket-a/*"),
		perm("s3:PutObject", "arn:aws:s3:::bucket-b/*"),
		perm("ec2:DescribeInstances", "*"),
	}
	got := GroupByResource(input)
	if len(got) != 3 {
		t.Fatalf("expected 3 resource keys, got %d: %v", len(got), got)
	}
	if actions := got["arn:aws:s3:::bucket-a/*"]; !reflect.DeepEqual(actions, []string{"s3:GetObject"}) {
		t.Errorf("bucket-a: want [s3:GetObject], got %v", actions)
	}
	if actions := got["arn:aws:s3:::bucket-b/*"]; !reflect.DeepEqual(actions, []string{"s3:PutObject"}) {
		t.Errorf("bucket-b: want [s3:PutObject], got %v", actions)
	}
	if actions := got["*"]; !reflect.DeepEqual(actions, []string{"ec2:DescribeInstances"}) {
		t.Errorf("wildcard: want [ec2:DescribeInstances], got %v", actions)
	}
}

func TestGroupByResource_MixedEmptyAndNonEmptyResource(t *testing.T) {
	input := []cloud.Permission{
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
		perm("sts:AssumeRole", ""),
		perm("sts:GetCallerIdentity", ""),
	}
	got := GroupByResource(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 keys (bucket and *), got %d: %v", len(got), got)
	}
	wildcard := got["*"]
	if len(wildcard) != 2 {
		t.Errorf("expected 2 actions under *, got %d: %v", len(wildcard), wildcard)
	}
}

func mapKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
