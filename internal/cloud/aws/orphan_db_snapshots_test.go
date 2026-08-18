package aws

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/nanohype/cloudgov/internal/cloud"
)

type snapMockRDS struct {
	instances []rdstypes.DBInstance
	clusters  []rdstypes.DBCluster
	snapshots []rdstypes.DBSnapshot
	clusterSn []rdstypes.DBClusterSnapshot

	instancesErr error
	clustersErr  error
	snapshotsErr error
	clusterSnErr error

	// lastSnapshotType records the SnapshotType filter the scanner asked for, so
	// a test can prove automated snapshots are excluded at the API rather than
	// filtered after the fact.
	lastSnapshotType        string
	lastClusterSnapshotType string
}

func (m *snapMockRDS) DescribeDBInstances(_ context.Context, _ *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if m.instancesErr != nil {
		return nil, m.instancesErr
	}
	return &rds.DescribeDBInstancesOutput{DBInstances: m.instances}, nil
}

func (m *snapMockRDS) DescribeDBClusters(_ context.Context, _ *rds.DescribeDBClustersInput, _ ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	if m.clustersErr != nil {
		return nil, m.clustersErr
	}
	return &rds.DescribeDBClustersOutput{DBClusters: m.clusters}, nil
}

func (m *snapMockRDS) DescribeDBSnapshots(_ context.Context, in *rds.DescribeDBSnapshotsInput, _ ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error) {
	m.lastSnapshotType = awssdk.ToString(in.SnapshotType)
	if m.snapshotsErr != nil {
		return nil, m.snapshotsErr
	}
	return &rds.DescribeDBSnapshotsOutput{DBSnapshots: m.snapshots}, nil
}

func (m *snapMockRDS) DescribeDBClusterSnapshots(_ context.Context, in *rds.DescribeDBClusterSnapshotsInput, _ ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error) {
	m.lastClusterSnapshotType = awssdk.ToString(in.SnapshotType)
	if m.clusterSnErr != nil {
		return nil, m.clusterSnErr
	}
	return &rds.DescribeDBClusterSnapshotsOutput{DBClusterSnapshots: m.clusterSn}, nil
}

func clusterSnapshot(id, source, status string, gb int32) rdstypes.DBClusterSnapshot {
	return rdstypes.DBClusterSnapshot{
		DBClusterSnapshotIdentifier: awssdk.String(id),
		DBClusterIdentifier:         awssdk.String(source),
		Status:                      awssdk.String(status),
		Engine:                      awssdk.String("aurora-postgresql"),
		AllocatedStorage:            awssdk.Int32(gb),
	}
}

func instanceSnapshot(id, source, status string, gb int32) rdstypes.DBSnapshot {
	return rdstypes.DBSnapshot{
		DBSnapshotIdentifier: awssdk.String(id),
		DBInstanceIdentifier: awssdk.String(source),
		Status:               awssdk.String(status),
		Engine:               awssdk.String("postgres"),
		AllocatedStorage:     awssdk.Int32(gb),
	}
}

func TestOrphanDBSnapshots(t *testing.T) {
	tests := []struct {
		name    string
		mock    *snapMockRDS
		wantIDs []string
	}{
		{
			// The shape found in the wild: a CloudFormation stack destroyed with
			// RemovalPolicy.SNAPSHOT, leaving a manual cluster snapshot whose
			// cluster no longer exists.
			name: "manual cluster snapshot whose cluster is gone is an orphan",
			mock: &snapMockRDS{
				clusters: nil,
				clusterSn: []rdstypes.DBClusterSnapshot{
					clusterSnapshot("dispatchstaging-snapshot-db", "dispatchstaging-db", "available", 0),
				},
			},
			wantIDs: []string{"dispatchstaging-snapshot-db"},
		},
		{
			name: "manual cluster snapshot whose cluster still exists is NOT an orphan",
			mock: &snapMockRDS{
				clusters: []rdstypes.DBCluster{
					{DBClusterIdentifier: awssdk.String("live-cluster")},
				},
				clusterSn: []rdstypes.DBClusterSnapshot{
					clusterSnapshot("live-cluster-snap", "live-cluster", "available", 0),
				},
			},
			wantIDs: []string{},
		},
		{
			name: "manual instance snapshot whose instance is gone is an orphan",
			mock: &snapMockRDS{
				snapshots: []rdstypes.DBSnapshot{
					instanceSnapshot("old-db-final", "old-db", "available", 200),
				},
			},
			wantIDs: []string{"old-db-final"},
		},
		{
			name: "manual instance snapshot whose instance still exists is NOT an orphan",
			mock: &snapMockRDS{
				instances: []rdstypes.DBInstance{
					{DBInstanceIdentifier: awssdk.String("prod-db")},
				},
				snapshots: []rdstypes.DBSnapshot{
					instanceSnapshot("prod-db-snap", "prod-db", "available", 200),
				},
			},
			wantIDs: []string{},
		},
		{
			// A snapshot mid-create or mid-delete is a transient the next scan
			// resolves; flagging it races the operation already handling it.
			name: "snapshot that is not available is skipped",
			mock: &snapMockRDS{
				clusterSn: []rdstypes.DBClusterSnapshot{
					clusterSnapshot("creating-snap", "gone-cluster", "creating", 0),
					clusterSnapshot("deleting-snap", "gone-cluster", "deleting", 0),
				},
			},
			wantIDs: []string{},
		},
		{
			name: "snapshot with no source identifier is skipped",
			mock: &snapMockRDS{
				clusterSn: []rdstypes.DBClusterSnapshot{
					clusterSnapshot("headless-snap", "", "available", 0),
				},
			},
			wantIDs: []string{},
		},
		{
			name: "both snapshot kinds are reported together",
			mock: &snapMockRDS{
				snapshots: []rdstypes.DBSnapshot{
					instanceSnapshot("inst-snap", "gone-instance", "available", 50),
				},
				clusterSn: []rdstypes.DBClusterSnapshot{
					clusterSnapshot("clus-snap", "gone-cluster", "available", 0),
				},
			},
			wantIDs: []string{"inst-snap", "clus-snap"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{rds: tt.mock, warnw: &bytes.Buffer{}}
			got, err := p.orphanDBSnapshots(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotIDs := make([]string, 0, len(got))
			for _, o := range got {
				gotIDs = append(gotIDs, o.ID)
			}
			if strings.Join(gotIDs, ",") != strings.Join(tt.wantIDs, ",") {
				t.Errorf("orphan IDs: got %v, want %v", gotIDs, tt.wantIDs)
			}
		})
	}
}

// TestOrphanDBSnapshots_OnlyManualRequested proves automated snapshots are excluded
// at the API. Automated snapshots are deleted with their database and cannot
// outlive it, so a stranded one does not exist — asking for them at all would
// invent orphans that AWS is already cleaning up.
func TestOrphanDBSnapshots_OnlyManualRequested(t *testing.T) {
	m := &snapMockRDS{}
	p := &Provider{rds: m, warnw: &bytes.Buffer{}}

	if _, err := p.orphanDBSnapshots(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.lastSnapshotType != "manual" {
		t.Errorf("db snapshot filter: got %q, want %q", m.lastSnapshotType, "manual")
	}
	if m.lastClusterSnapshotType != "manual" {
		t.Errorf("db cluster snapshot filter: got %q, want %q", m.lastClusterSnapshotType, "manual")
	}
}

// TestOrphanDBSnapshots_LiveIndexFailureReportsNothing is the safety property that
// matters most here. If the live-database lookup fails, every snapshot in the
// account looks stranded — and this scanner feeds a generator that emits
// `aws rds delete-db-snapshot`. A denied DescribeDBInstances must produce no
// findings at all, never a script that deletes every backup the account has.
func TestOrphanDBSnapshots_LiveIndexFailureReportsNothing(t *testing.T) {
	for _, tt := range []struct {
		name string
		mock *snapMockRDS
	}{
		{
			name: "instance lookup denied",
			mock: &snapMockRDS{
				instancesErr: errors.New("AccessDenied"),
				snapshots:    []rdstypes.DBSnapshot{instanceSnapshot("snap", "some-db", "available", 100)},
				clusterSn:    []rdstypes.DBClusterSnapshot{clusterSnapshot("csnap", "some-cluster", "available", 0)},
			},
		},
		{
			name: "cluster lookup denied",
			mock: &snapMockRDS{
				clustersErr: errors.New("AccessDenied"),
				snapshots:   []rdstypes.DBSnapshot{instanceSnapshot("snap", "some-db", "available", 100)},
				clusterSn:   []rdstypes.DBClusterSnapshot{clusterSnapshot("csnap", "some-cluster", "available", 0)},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{rds: tt.mock, warnw: &bytes.Buffer{}}
			got, err := p.orphanDBSnapshots(context.Background())
			if err == nil {
				t.Fatal("a failed live-database lookup must return an error, not an empty live set")
			}
			if len(got) != 0 {
				t.Fatalf("no snapshot may be reported when the live set is unknown, got %d", len(got))
			}
		})
	}
}

// TestOrphanDBSnapshots_SnapshotPageErrorIsRecorded pins that an unreadable
// snapshot page warns rather than silently narrowing the result.
func TestOrphanDBSnapshots_SnapshotPageErrorIsRecorded(t *testing.T) {
	var warn bytes.Buffer
	p := &Provider{
		rds:   &snapMockRDS{snapshotsErr: errors.New("AccessDenied")},
		warnw: &warn,
	}

	if _, err := p.orphanDBSnapshots(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Incomplete()) == 0 {
		t.Fatal("an unreadable snapshot page must be recorded as an incomplete observation")
	}
	if !strings.Contains(warn.String(), "db snapshots") {
		t.Errorf("warning should name the failed call, got %q", warn.String())
	}
}

func TestOrphanDBSnapshots_CostAndDetail(t *testing.T) {
	tests := []struct {
		name           string
		mock           *snapMockRDS
		wantKind       cloud.OrphanKind
		wantCost       float64
		detailContains []string
	}{
		{
			name: "sized instance snapshot is priced at the RDS backup rate",
			mock: &snapMockRDS{
				snapshots: []rdstypes.DBSnapshot{instanceSnapshot("snap", "gone-db", "available", 200)},
			},
			wantKind:       cloud.OrphanDBSnapshot,
			wantCost:       200 * rdsBackupGBMonth,
			detailContains: []string{"gone-db", "200 GB", "on-demand"},
		},
		{
			// Aurora reports AllocatedStorage 0 on cluster snapshots. Reporting
			// "$0.00/mo" there would read as free; the detail has to say unknown.
			name: "aurora cluster snapshot reports unknown size, not free",
			mock: &snapMockRDS{
				clusterSn: []rdstypes.DBClusterSnapshot{clusterSnapshot("csnap", "gone-cluster", "available", 0)},
			},
			wantKind:       cloud.OrphanDBClusterSnapshot,
			wantCost:       0,
			detailContains: []string{"gone-cluster", "size not reported"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{rds: tt.mock, warnw: &bytes.Buffer{}, cfg: awssdk.Config{Region: "us-west-2"}}
			got, err := p.orphanDBSnapshots(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("want 1 orphan, got %d", len(got))
			}
			o := got[0]
			if o.Kind != tt.wantKind {
				t.Errorf("kind: got %v, want %v", o.Kind, tt.wantKind)
			}
			if o.MonthlyCost != tt.wantCost {
				t.Errorf("monthly cost: got %v, want %v", o.MonthlyCost, tt.wantCost)
			}
			if o.Region != "us-west-2" {
				t.Errorf("region: got %q, want %q", o.Region, "us-west-2")
			}
			for _, want := range tt.detailContains {
				if !strings.Contains(o.Detail, want) {
					t.Errorf("detail %q should contain %q", o.Detail, want)
				}
			}
		})
	}
}
