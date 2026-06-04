package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/nanohype/cloudgov/internal/cloud"
)

func ebsImage(id, name, snapID string, sizeGB int32) ec2types.Image {
	return ec2types.Image{
		ImageId: awssdk.String(id),
		Name:    awssdk.String(name),
		BlockDeviceMappings: []ec2types.BlockDeviceMapping{{
			Ebs: &ec2types.EbsBlockDevice{
				SnapshotId: awssdk.String(snapID),
				VolumeSize: awssdk.Int32(sizeGB),
			},
		}},
	}
}

func TestOrphanSnapshots(t *testing.T) {
	// ami-live backs snap-backing; ami-dead is gone.
	mock := &mockEC2{
		imagesOut: []ec2types.Image{ebsImage("ami-live", "live-ami", "snap-backing", 20)},
		snapshotPages: [][]ec2types.Snapshot{{
			{SnapshotId: awssdk.String("snap-backing"), VolumeSize: awssdk.Int32(20),
				Description: awssdk.String("Created by CreateImage(i-1) for ami-live from vol-1")}, // backs a live AMI → skip
			{SnapshotId: awssdk.String("snap-dead"), VolumeSize: awssdk.Int32(8),
				Description: awssdk.String("Created by CreateImage(i-2) for ami-dead from vol-2")}, // AMI gone → orphan
			{SnapshotId: awssdk.String("snap-liveref"), VolumeSize: awssdk.Int32(8),
				Description: awssdk.String("Created by CreateImage(i-3) for ami-live from vol-3")}, // refs a live AMI → skip
			{SnapshotId: awssdk.String("snap-manual"), VolumeSize: awssdk.Int32(100),
				Description: awssdk.String("nightly db backup")}, // manual backup → never flagged
		}},
	}

	got, err := (&Provider{ec2: mock}).orphanSnapshots(context.Background())
	if err != nil {
		t.Fatalf("orphanSnapshots: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 orphan snapshot, got %d: %+v", len(got), got)
	}
	o := got[0]
	if o.Kind != cloud.OrphanSnapshot || o.ID != "snap-dead" {
		t.Errorf("got %+v, want OrphanSnapshot snap-dead", o)
	}
	if o.MonthlyCost != 8*ebsSnapshotGBMonth {
		t.Errorf("cost: got %v, want %v", o.MonthlyCost, 8*ebsSnapshotGBMonth)
	}
}

func TestOrphanSnapshots_PageErrorWarnsAndBreaks(t *testing.T) {
	mock := &mockEC2{snapshotsErr: errors.New("throttled")}
	got, err := (&Provider{ec2: mock}).orphanSnapshots(context.Background())
	if err != nil {
		t.Fatalf("want nil error (warn-and-break), got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no orphans, got %+v", got)
	}
}

func TestOrphanImages(t *testing.T) {
	mock := &mockEC2{
		imagesOut: []ec2types.Image{
			ebsImage("ami-used", "in-use", "snap-a", 10),
			ebsImage("ami-unused", "stale", "snap-b", 30),
			ebsImage("ami-noname", "", "snap-c", 5),
		},
		instancesOut: []ec2types.Reservation{{
			Instances: []ec2types.Instance{{ImageId: awssdk.String("ami-used")}},
		}},
	}

	got, err := (&Provider{ec2: mock}).orphanImages(context.Background())
	if err != nil {
		t.Fatalf("orphanImages: %v", err)
	}
	byID := map[string]cloud.OrphanResource{}
	for _, o := range got {
		if o.Kind != cloud.OrphanImage {
			t.Errorf("kind: got %v", o.Kind)
		}
		byID[o.ID] = o
	}
	if _, used := byID["ami-used"]; used {
		t.Errorf("in-use AMI was flagged: %+v", byID["ami-used"])
	}
	if o, ok := byID["ami-unused"]; !ok {
		t.Errorf("unused AMI not flagged")
	} else if o.MonthlyCost != 30*ebsSnapshotGBMonth {
		t.Errorf("cost: got %v, want %v", o.MonthlyCost, 30*ebsSnapshotGBMonth)
	}
	if o, ok := byID["ami-noname"]; !ok {
		t.Errorf("unused no-name AMI not flagged")
	} else if o.Name != "ami-noname" {
		t.Errorf("empty Name should fall back to id, got %q", o.Name)
	}
}

func TestOrphanImages_NoImagesSkipsInstanceScan(t *testing.T) {
	got, err := (&Provider{ec2: &mockEC2{}}).orphanImages(context.Background())
	if err != nil {
		t.Fatalf("orphanImages: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no orphans, got %+v", got)
	}
}

func TestAMIIDFromSnapshotDescription(t *testing.T) {
	cases := map[string]string{
		"Created by CreateImage(i-abc) for ami-0123abc from vol-9": "ami-0123abc",
		"Created by CreateImage(i-abc) for ami-deadbeef":           "ami-deadbeef",
		"Created by CreateImage(i-abc)":                            "", // no "for ami-"
		"nightly db backup":                                        "", // not an AMI-creation desc
		"Copied for DestinationAmi ami-xyz from region":            "", // wrong prefix
		"": "",
	}
	for desc, want := range cases {
		if got := amiIDFromSnapshotDescription(desc); got != want {
			t.Errorf("amiIDFromSnapshotDescription(%q) = %q, want %q", desc, got, want)
		}
	}
}
