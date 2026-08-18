package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/nanohype/cloudgov/internal/cloud"
)

// Backup storage on-demand list prices (us-east-1), used to estimate what a
// stranded manual snapshot costs to keep. Aurora bills cluster snapshots at a
// different rate than RDS instance snapshots, so the two are kept apart rather
// than averaged into one number that is wrong for both.
const (
	rdsBackupGBMonth    = 0.095
	auroraBackupGBMonth = 0.021
)

// snapshotAvailable is the only DB snapshot status worth reporting. A snapshot
// mid-create or mid-delete is a transient the next scan will resolve, and
// flagging one races the operation that is already handling it.
const snapshotAvailable = "available"

// orphanDBSnapshots finds manual RDS snapshots whose source database is gone.
//
// Deleting a DB instance or cluster removes its automated backups but never its
// manual snapshots — that asymmetry is the whole point of the manual type, and it
// is also why manual snapshots are the RDS resource most likely to be paying for
// storage nobody remembers taking. CloudFormation and CDK make it routine:
// RemovalPolicy.SNAPSHOT takes a final manual snapshot on every stack destroy, so
// a staging stack torn down and re-deployed ten times leaves ten of them.
//
// Automated snapshots are never flagged: they are deleted with their instance and
// cannot outlive it, so a stranded one does not exist.
func (p *Provider) orphanDBSnapshots(ctx context.Context) ([]cloud.OrphanResource, error) {
	liveInstances, liveClusters, err := p.liveDatabaseIndex(ctx)
	if err != nil {
		return nil, err
	}

	var orphans []cloud.OrphanResource
	orphans = append(orphans, p.strandedInstanceSnapshots(ctx, liveInstances)...)
	orphans = append(orphans, p.strandedClusterSnapshots(ctx, liveClusters)...)
	return orphans, nil
}

// liveDatabaseIndex returns the set of DB instance and DB cluster identifiers that
// still exist, so a snapshot can be checked against what is actually running.
//
// A failure here is fatal to the check rather than warned-and-skipped: an empty
// live set makes every snapshot in the account look stranded, which would turn a
// denied DescribeDBInstances into a script that deletes every backup the account
// has. The scan reports nothing here rather than something catastrophic.
func (p *Provider) liveDatabaseIndex(ctx context.Context) (instances, clusters map[string]bool, err error) {
	instances = map[string]bool{}
	clusters = map[string]bool{}

	instPager := rds.NewDescribeDBInstancesPaginator(p.rds, &rds.DescribeDBInstancesInput{})
	for instPager.HasMorePages() {
		page, err := instPager.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("describe db instances: %w", err)
		}
		for _, db := range page.DBInstances {
			instances[awssdk.ToString(db.DBInstanceIdentifier)] = true
		}
	}

	clusterPager := rds.NewDescribeDBClustersPaginator(p.rds, &rds.DescribeDBClustersInput{})
	for clusterPager.HasMorePages() {
		page, err := clusterPager.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("describe db clusters: %w", err)
		}
		for _, c := range page.DBClusters {
			clusters[awssdk.ToString(c.DBClusterIdentifier)] = true
		}
	}

	return instances, clusters, nil
}

func (p *Provider) strandedInstanceSnapshots(ctx context.Context, live map[string]bool) []cloud.OrphanResource {
	pager := rds.NewDescribeDBSnapshotsPaginator(p.rds, &rds.DescribeDBSnapshotsInput{
		SnapshotType: awssdk.String("manual"),
	})

	var orphans []cloud.OrphanResource
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			p.warnf("warn: describe db snapshots page: %v\n", err)
			break
		}
		for _, s := range page.DBSnapshots {
			source := awssdk.ToString(s.DBInstanceIdentifier)
			if source == "" || live[source] || awssdk.ToString(s.Status) != snapshotAvailable {
				continue
			}
			gb := int(awssdk.ToInt32(s.AllocatedStorage))
			orphans = append(orphans, cloud.OrphanResource{
				Kind:        cloud.OrphanDBSnapshot,
				ID:          awssdk.ToString(s.DBSnapshotIdentifier),
				Name:        awssdk.ToString(s.DBSnapshotIdentifier),
				Region:      p.cfg.Region,
				Provider:    "aws",
				MonthlyCost: float64(gb) * rdsBackupGBMonth,
				Detail:      snapshotDetail("db instance", source, awssdk.ToString(s.Engine), gb, rdsBackupGBMonth),
			})
		}
	}
	return orphans
}

func (p *Provider) strandedClusterSnapshots(ctx context.Context, live map[string]bool) []cloud.OrphanResource {
	pager := rds.NewDescribeDBClusterSnapshotsPaginator(p.rds, &rds.DescribeDBClusterSnapshotsInput{
		SnapshotType: awssdk.String("manual"),
	})

	var orphans []cloud.OrphanResource
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			p.warnf("warn: describe db cluster snapshots page: %v\n", err)
			break
		}
		for _, s := range page.DBClusterSnapshots {
			source := awssdk.ToString(s.DBClusterIdentifier)
			if source == "" || live[source] || awssdk.ToString(s.Status) != snapshotAvailable {
				continue
			}
			gb := int(awssdk.ToInt32(s.AllocatedStorage))
			orphans = append(orphans, cloud.OrphanResource{
				Kind:        cloud.OrphanDBClusterSnapshot,
				ID:          awssdk.ToString(s.DBClusterSnapshotIdentifier),
				Name:        awssdk.ToString(s.DBClusterSnapshotIdentifier),
				Region:      p.cfg.Region,
				Provider:    "aws",
				MonthlyCost: float64(gb) * auroraBackupGBMonth,
				Detail:      snapshotDetail("db cluster", source, awssdk.ToString(s.Engine), gb, auroraBackupGBMonth),
			})
		}
	}
	return orphans
}

// snapshotDetail explains which database the snapshot outlived and what keeping it
// costs. Aurora reports AllocatedStorage as 0 on cluster snapshots because its
// storage is elastic and billed on actual backup bytes, which no describe call
// returns — so the size is reported as unknown rather than as an estimate of $0.00
// that reads like "free".
func snapshotDetail(sourceKind, source, engine string, gb int, ratePerGBMonth float64) string {
	if gb <= 0 {
		return fmt.Sprintf("manual %s snapshot; source %s %q no longer exists; size not reported by the API (Aurora bills actual backup bytes at ~$%.3f/GB-month on-demand)",
			engine, sourceKind, source, ratePerGBMonth)
	}
	return fmt.Sprintf("manual %s snapshot; source %s %q no longer exists; %d GB at ~$%.3f/GB-month on-demand",
		engine, sourceKind, source, gb, ratePerGBMonth)
}
