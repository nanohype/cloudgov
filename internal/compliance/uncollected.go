package compliance

// A control cloudgov cannot answer says what would answer it.
//
// Two evaluators once stood in for these: given any non-empty report they
// returned PASS without reading the control or any finding, so eight CIS
// controls — root access keys, root MFA and EBS encryption among them — reported
// PASS on every account ever scanned, with the detail "no relevant findings
// detected". That sentence was true and completely misleading: nothing relevant
// could have been detected, because the data was never collected.
//
// The answer is a table rather than an evaluator. A function handed findings has
// to decide something, and the decision it can reach from findings about a
// different control is the one that went wrong. A control listed here reaches no
// evaluator at all, so there is no branch to get this wrong in.
//
// Each entry names the probe that would answer the control, not the fact that
// none exists. "Not evaluated" tells an auditor the tool declined; naming the
// missing collector tells them what closes it, and turns each line into a piece
// of work rather than a permanent shrug.
//
// TestEveryPublishedControlCanFailOrNamesWhatIsMissing requires every published
// control to be either here or shown to FAIL on some input, so a control added
// to a benchmark cannot ship with no verdict and no explanation.

// uncollectedDetail renders one entry as the detail an auditor reads.
func uncollectedDetail(probe string) string {
	return "cloudgov does not collect the data this control needs: " + probe +
		". Findings loaded from other domains are context, not a verdict on this control."
}

// cisUncollected names the CIS AWS v3 controls no scan cloudgov runs can answer.
var cisUncollected = map[string]string{
	"1.4":  "the IAM credential report's root access-key columns; no scan reads root credential state",
	"1.5":  "the IAM account summary's root MFA field; no scan reads root credential state",
	"1.17": "the support role's existence and trust policy; the IAM scan reads the principals it finds, not one it expects to find",
	"1.19": "each EC2 instance's instance profile; no scan enumerates instance-to-role attachment",
	"1.22": "policy attachment for AWSCloudShellFullAccess by name; the IAM scan classifies permissions rather than tracking named managed policies",

	"2.1.1": "each bucket's policy document; the storage scan reads encryption, versioning, logging and public-access state, not policies",
	"2.1.2": "each bucket's MFA Delete state, which lives on the versioning subresource and is not read",
	"2.2.1": "EBS encryption-by-default per region and each volume's encryption state; no scan reads EBS",

	"3.1": "CloudTrail trail configuration; the IAM scan reads CloudTrail events, not the trails that produce them",
	"3.4": "each trail's log-file-validation setting; trail configuration is not read",

	// Routed here rather than to a network finding type, because none of them
	// answers this control and the closest one was wrong in both directions. It
	// fired on any security group with an open non-admin port, so 5.4 failed with
	// evidence naming a group it does not govern; and a stock default group
	// permits all traffic from itself through UserIdGroupPairs, which the scanner
	// never harvests — so the exact condition this control exists to catch
	// produced no finding at all.
	"5.4": "each VPC's default security group, with a rule permitting all traffic from the group itself read as permissive; the network scan harvests only literal 0.0.0.0/0 CIDRs",
}

// soc2Uncollected names the SOC 2 Type II criteria no scan cloudgov runs can
// answer. Most need evidence that is not in any cloud API.
var soc2Uncollected = map[string]string{
	"CC1.1": "the organization's documented values and conduct standards, and evidence they are communicated; no API carries this",
	"CC2.1": "the information and communication policies themselves, and evidence of their distribution; no API carries this",
	"CC3.1": "the risk assessment process and its recorded output; no API carries this",
	"CC4.1": "the monitoring procedures and evidence they were performed; no API carries this",
	"CC5.1": "the control activities the organization selected and how it did so; no API carries this",
	"CC7.1": "configuration change history against an approved baseline; the IAM scan reads current state, and no scan report this benchmark loads carries change-monitoring evidence",
	"CC8.1": "the change management process and its approval records; no API carries this",
	"CC9.1": "vendor agreements and their scope; no API carries this",
}
